-- Keep provider OAuth credentials outside the organization-readable integration configuration.
create table if not exists public.security_integration_secrets (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  integration_id uuid not null references public.security_integrations(id) on delete cascade,
  provider text not null,
  access_token_encrypted text not null,
  refresh_token_encrypted text,
  token_type text not null default 'Bearer',
  scopes jsonb not null default '[]'::jsonb,
  expires_at timestamptz,
  authorized_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(integration_id)
);

create index if not exists security_integration_secrets_org_idx
  on public.security_integration_secrets(organization_id);

alter table public.security_integration_secrets enable row level security;

-- No authenticated-user policy is intentionally granted. Provider credentials
-- are server-side secrets and are accessed only through the service role.
