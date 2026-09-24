-- SentinelX secure integration ingestion credentials
-- Stores only a SHA-256 hash and a short display prefix. Plaintext tokens are never persisted.

alter table public.security_integrations
  add column if not exists ingestion_token_hash text,
  add column if not exists ingestion_token_prefix text,
  add column if not exists ingestion_token_created_at timestamptz,
  add column if not exists ingestion_token_last_used_at timestamptz;

create unique index if not exists security_integrations_ingestion_token_hash_idx
  on public.security_integrations(ingestion_token_hash)
  where ingestion_token_hash is not null;
