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

create or replace function public.verify_security_ingestion_token(
  p_token_hash text
)
returns table (
  integration_id uuid,
  organization_id uuid,
  provider text,
  integration_type text
)
language sql
security definer
set search_path = public
as $$
  select
    si.id,
    si.organization_id,
    si.provider,
    si.integration_type
  from public.security_integrations si
  where si.ingestion_token_hash = p_token_hash
    and si.status in ('planned', 'pending', 'connected')
  limit 1;
$$;

revoke all on function public.verify_security_ingestion_token(text) from public;
grant execute on function public.verify_security_ingestion_token(text) to anon, authenticated;
