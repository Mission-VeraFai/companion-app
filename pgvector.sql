-- Reference: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase#create-a-table-and-search-function-in-your-database
-- Uses pgvector with an approved embedding model from the organization registry
-- Enable the pgvector extension to work with embedding vectors
create extension vector;

-- Create a table to store your documents
create table documents (
  id bigserial primary key,
  content text, -- corresponds to Document.pageContent
  metadata jsonb, -- corresponds to Document.metadata
  embedding vector(768) -- 768 dimensions for approved registry model: text-embedding-3-small
);

-- Audit log table for AI-driven vector similarity retrievals
create table if not exists match_documents_audit_log (
  id               bigserial primary key,
  correlation_id   uuid        not null default gen_random_uuid(),
  occurred_at      timestamptz not null default now(),
  principal        text        not null,
  model_id         text        not null          -- identifier of the AI model/embedding used
    check (model_id = 'text-embedding-3-small'),
  input_hash       text        not null,          -- SHA-256 hex of the serialised query_embedding
  match_count      int,
  filter           jsonb,
  output_summary   jsonb,                         -- result count and top similarity score
  retention_expires_at timestamptz not null       -- records must be retained until this date
    default (now() + interval '7 years')
);

-- Append-only enforcement: block UPDATE and DELETE on the audit log
create or replace function audit_log_append_only()
returns trigger language plpgsql as $fn$
begin
  raise exception
    'Audit log is append-only: % operations are not permitted on match_documents_audit_log',
    TG_OP;
end;
$fn$;

drop trigger if exists trg_audit_log_no_update on match_documents_audit_log;
create trigger trg_audit_log_no_update
  before update on match_documents_audit_log
  for each row execute function audit_log_append_only();

drop trigger if exists trg_audit_log_no_delete on match_documents_audit_log;
create trigger trg_audit_log_no_delete
  before delete on match_documents_audit_log
  for each row execute function audit_log_append_only();

-- ----------------------------------------------------------------
-- HITL (Human-in-the-Loop) approval flow for DELETE on documents
-- ----------------------------------------------------------------

-- Queue table: every delete request must be approved by a human before execution
create table if not exists pending_document_deletions (
  request_id      bigserial primary key,
  document_id     bigint      not null references documents(id),
  requested_by    text        not null,
  requested_at    timestamptz not null default now(),
  reason          text,
  status          text        not null default 'PENDING'
    check (status in ('PENDING', 'APPROVED', 'REJECTED')),
  reviewed_by     text,
  reviewed_at     timestamptz
);

-- Step 1 – submit a delete request (no data is removed yet)
create or replace function request_document_deletion(
  p_document_id  bigint,
  p_requested_by text,
  p_reason       text default null
) returns bigint language plpgsql as $fn$
declare
  v_request_id bigint;
begin
  if p_document_id is null then
    raise exception 'request_document_deletion: document_id must not be null';
  end if;
  if p_requested_by is null or trim(p_requested_by) = '' then
    raise exception 'request_document_deletion: requested_by must not be empty';
  end if;

  insert into pending_document_deletions (document_id, requested_by, reason)
  values (p_document_id, p_requested_by, p_reason)
  returning request_id into v_request_id;

  raise notice
    'Delete request % created for document %. Awaiting human approval.',
    v_request_id, p_document_id;

  return v_request_id;
end;
$fn$;

-- Step 2 – a human approver explicitly approves and triggers the delete
create or replace function approve_document_deletion(
  p_request_id  bigint,
  p_reviewed_by text
) returns void language plpgsql as $fn$
declare
  v_doc_id bigint;
  v_status text;
begin
  if p_reviewed_by is null or trim(p_reviewed_by) = '' then
    raise exception 'approve_document_deletion: reviewed_by must not be empty';
  end if;

  select document_id, status
    into v_doc_id, v_status
    from pending_document_deletions
   where request_id = p_request_id
     for update;

  if not found then
    raise exception 'approve_document_deletion: request % not found', p_request_id;
  end if;

  if v_status <> 'PENDING' then
    raise exception
      'approve_document_deletion: request % is already in status %, cannot approve',
      p_request_id, v_status;
  end if;

  -- Record the human approval
  update pending_document_deletions
     set status      = 'APPROVED',
         reviewed_by = p_reviewed_by,
         reviewed_at = now()
   where request_id = p_request_id;

  -- Now perform the actual delete
  delete from documents where id = v_doc_id;

  raise notice
    'Document % deleted by human approver % (request %).',
    v_doc_id, p_reviewed_by, p_request_id;
end;
$fn$;

-- Trigger function: block direct DELETEs on documents and redirect to HITL flow
create or replace function documents_require_hitl_approval()
returns trigger language plpgsql as $fn$
begin
  raise exception
    'Direct DELETE on documents is not permitted. '
    'Submit a delete request via request_document_deletion(document_id, requested_by) '
    'and obtain human approval via approve_document_deletion(request_id, reviewed_by).';
end;
$fn$;

drop trigger if exists trg_documents_hitl_delete on documents;
create trigger trg_documents_hitl_delete
  before delete on documents
  for each row execute function documents_require_hitl_approval();

-- Create a function to search for documents
create function match_documents (
  query_embedding vector(768),
  match_count int DEFAULT null,
  filter jsonb DEFAULT '{}',
  model_id text DEFAULT 'text-embedding-3-small'
) returns table (
  content      text,    -- truncated excerpt (max 1000 chars)
  similarity   float,
  -- Provenance / synthetic-origin metadata (policy: AI content labeling)
  ai_generated boolean, -- always TRUE: content was retrieved via AI embedding similarity
  model_identifier text, -- identifier of the embedding model used for retrieval
  content_origin   text, -- tag indicating this row originates from a vector-similarity search
  retrieved_at     timestamptz -- UTC timestamp of retrieval for audit trail
)
language plpgsql
as $$
#variable_conflict use_column
declare
  _safe_match_count int;
  _safe_filter       jsonb;
begin
  -- ----------------------------------------------------------------
  -- Input validation & sanitisation
  -- ----------------------------------------------------------------

  -- 1. Validate query_embedding: must not be NULL
  if query_embedding is null then
    raise exception 'match_documents: query_embedding must not be null';
  end if;

  -- 2. Validate and clamp match_count to a safe positive range [1, 1000]
  if match_count is null then
    _safe_match_count := 10;          -- sensible default
  elsif match_count < 1 then
    raise exception 'match_documents: match_count must be >= 1, got %', match_count;
  elsif match_count > 1000 then
    raise exception 'match_documents: match_count must be <= 1000, got %', match_count;
  else
    _safe_match_count := match_count;
  end if;

  -- 3. Validate and sanitise filter
  --    a. Treat NULL as empty object
  if filter is null then
    _safe_filter := '{}'::jsonb;
  --    b. Reject non-object JSON types (arrays, scalars, etc.)
  elsif jsonb_typeof(filter) <> 'object' then
    raise exception 'match_documents: filter must be a JSON object, got %', jsonb_typeof(filter);
  --    c. Reject unreasonably large filters (> 8 kB serialised) to prevent DoS
  elsif octet_length(filter::text) > 8192 then
    raise exception 'match_documents: filter exceeds maximum allowed size (8192 bytes)';
  else
    -- Strip any keys whose names contain SQL meta-characters or are empty
    -- to prevent injection through key names used in dynamic contexts.
    select jsonb_object_agg(key, value)
      into _safe_filter
      from jsonb_each(filter)
     where key ~ '^[A-Za-z0-9_\-\.]+$'   -- allow only safe key characters
       and key <> '';                      -- discard empty-string keys

    -- If all keys were stripped, fall back to empty object
    if _safe_filter is null then
      _safe_filter := '{}'::jsonb;
    end if;
  end if;

  -- ----------------------------------------------------------------
  -- Audit: record every invocation using sanitised values only
  -- ----------------------------------------------------------------
  insert into match_documents_audit_log (
    principal, model_id, input_hash, match_count, filter, output_summary
  )
  values (
    current_user,
    model_id,
    encode(sha256(query_embedding::text::bytea), 'hex'),
    _safe_match_count,
    _safe_filter,
    jsonb_build_object(
      'requested_match_count', _safe_match_count,
      'filter_keys', (select jsonb_agg(key) from jsonb_each(_safe_filter)),
      'model_id', model_id,
      'retrieval_type', 'vector-similarity-retrieval',
      'retrieved_at', now()
    )
  );

  -- ----------------------------------------------------------------
  -- Main query using sanitised inputs
  -- ----------------------------------------------------------------
  return query
  select
    left(documents.content, 1000) as content, -- truncate to 1000 chars to enforce output data minimisation
    1 - (documents.embedding <=> query_embedding) as similarity,
    -- Provenance / synthetic-origin labels (policy: AI content labeling & watermarking)
    true                                    as ai_generated,
    model_id                                as model_identifier,
    'vector-similarity-retrieval'           as content_origin,
    now()                                   as retrieved_at
  from documents
  where metadata @> _safe_filter
  order by documents.embedding <=> query_embedding
  limit _safe_match_count;
end;
$$;
