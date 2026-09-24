-- SentinelX Security Brain relationship lifecycle + evidence ingestion
-- Keeps discovered relationships separate from operator-confirmed relationships.

alter table public.security_asset_relationships
  add column if not exists status text not null default 'confirmed'
  check (status in ('proposed','confirmed','rejected'));

alter table public.security_asset_relationships
  add column if not exists evidence_source text not null default 'operator';

alter table public.security_asset_relationships
  add column if not exists discovered_at timestamptz;

create index if not exists security_relationships_status_idx
  on public.security_asset_relationships(organization_id, status);

create table if not exists public.security_evidence (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  asset_id uuid references public.security_assets(id) on delete set null,
  evidence_type text not null,
  source text not null,
  title text not null,
  summary text,
  data jsonb not null default '{}'::jsonb,
  observed_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create index if not exists security_evidence_org_time_idx
  on public.security_evidence(organization_id, observed_at desc);

create index if not exists security_evidence_asset_idx
  on public.security_evidence(asset_id);

alter table public.security_evidence enable row level security;

drop policy if exists "security_evidence_org_access" on public.security_evidence;
create policy "security_evidence_org_access" on public.security_evidence
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));

-- Existing operator-created relationships remain confirmed.
update public.security_asset_relationships
set status = 'confirmed',
    evidence_source = case
      when evidence->>'source' = 'operator_provided' then 'operator'
      else coalesce(nullif(evidence->>'source', ''), 'operator')
    end
where status is null;
