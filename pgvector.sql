-- Reference: https://js.langchain.com/docs/modules/indexes/vector_stores/integrations/supabase#create-a-table-and-search-function-in-your-database
-- Visit Supabase blogpost for more: https://supabase.com/blog/openai-embeddings-postgres-vector
-- Enable the pgvector extension to work with embedding vectors
create extension vector;

-- Create a table to store your documents
create table documents (
  id bigserial primary key,
  content text, -- corresponds to Document.pageContent
  metadata jsonb, -- corresponds to Document.metadata
  embedding vector(1536) -- 1536 works for OpenAI embeddings, change if needed
);

-- Create a function to search for documents
create function match_documents (
  query_embedding vector(1536),
  match_count int DEFAULT null,
  filter jsonb DEFAULT '{}'
) returns table (
  content text,
  source text,
  similarity float
)
language plpgsql
as $$
#variable_conflict use_column
begin
  -- Validate query_embedding is not null
  if query_embedding is null then
    raise exception 'query_embedding must not be null';
  end if;

  -- Validate match_count is within a safe range
  if match_count is not null and (match_count < 1 or match_count > 1000) then
    raise exception 'match_count must be between 1 and 1000';
  end if;

  -- Validate filter is not null
  if filter is null then
    raise exception 'filter must not be null';
  end if;

  -- Validate filter is a JSON object (not an array, scalar, etc.)
  if jsonb_typeof(filter) <> 'object' then
    raise exception 'filter must be a JSON object';
  end if;

  -- Validate filter does not exceed a reasonable size to prevent abuse
  if octet_length(filter::text) > 4096 then
    raise exception 'filter exceeds maximum allowed size';
  end if;

  -- Validate filter keys are non-empty strings (no empty-key injection)
  if exists (
    select 1 from jsonb_object_keys(filter) as k where k = ''
  ) then
    raise exception 'filter contains invalid empty key';
  end if;

  return query
  select
    content,
    -- Expose only the 'source' key from metadata; add other safe keys as needed.
    -- Raw internal id and full metadata jsonb are intentionally excluded.
    (metadata->>'source')::text as source,
    1 - (documents.embedding <=> query_embedding) as similarity
  from documents
  where metadata @> filter
  order by documents.embedding <=> query_embedding
  limit match_count;
end;
$$;
