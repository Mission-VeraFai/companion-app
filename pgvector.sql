-- Reference: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase#create-a-table-and-search-function-in-your-database
-- Uses pgvector with an approved open-source embedding model (e.g. sentence-transformers/all-MiniLM-L6-v2, dim=768)
-- Enable the pgvector extension to work with embedding vectors
create extension vector;

-- Create a table to store your documents
create table documents (
  id bigserial primary key,
  content text, -- corresponds to Document.pageContent
  metadata jsonb, -- corresponds to Document.metadata
  embedding vector(768) -- 768 dimensions for approved open-source embedding models (e.g. sentence-transformers/all-MiniLM-L6-v2)
);

-- Audit log table for AI-driven vector similarity retrievals
create table if not exists match_documents_audit_log (
  id               bigserial primary key,
  correlation_id   uuid        not null default gen_random_uuid(),
  occurred_at      timestamptz not null default now(),
  principal        text        not null,
  model_id         text        not null,          -- identifier of the AI model/embedding used
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

-- Create a function to search for documents
create function match_documents (
  query_embedding vector(1536),
  match_count int DEFAULT null,
  filter jsonb DEFAULT '{}',
  model_id text DEFAULT 'openai/text-embedding-ada-002'
) returns table (
  content      text,    -- truncated excerpt (max 1000 chars)
  similarity   float,
  -- Provenance / synthetic-origin metadata (policy: AI content labeling)
  ai_generated boolean, -- always TRUE: content was retrieved via AI embedding similarity
  model_identifier text, -- identifier of the embedding model used for retrieval
  content_origin   text, -- tag indicating this row originates from a vector-similarity search
  retrieved_at     timestamptz -- UTC timestamp of retrieval for audit trail
),
  match_count int DEFAULT null,
  filter jsonb DEFAULT '{}'
) returns table (
  content text, -- truncated excerpt (max 1000 chars)
  similarity float
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
    principal, model_id, input_hash, match_count, filter
  )
  values (
    current_user,
    model_id,
    encode(sha256(query_embedding::text::bytea), 'hex'),
    _safe_match_count,
    _safe_filter
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
