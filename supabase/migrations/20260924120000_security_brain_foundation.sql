-- SentinelX Security Brain foundation
-- Safe to run after the existing SentinelX organization/profile setup.
-- This migration adds the security graph, evidence, integrations and AI-security layer.

create extension if not exists pgcrypto;

create table if not exists public.security_assets (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  asset_type text not null check (asset_type in (
    'website','domain','cloud','identity','endpoint','email',
    'business_software','database','ai_system','ai_agent','api','other'
  )),
  external_id text,
  provider text,
  environment text not null default 'production',
  criticality text not null default 'medium' check (criticality in ('low','medium','high','critical')),
  status text not null default 'active' check (status in ('active','inactive','unknown')),
  metadata jsonb not null default '{}'::jsonb,
  last_seen_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists security_assets_org_idx on public.security_assets(organization_id);
create index if not exists security_assets_type_idx on public.security_assets(organization_id, asset_type);

create table if not exists public.security_asset_relationships (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  source_asset_id uuid not null references public.security_assets(id) on delete cascade,
  target_asset_id uuid not null references public.security_assets(id) on delete cascade,
  relationship_type text not null,
  confidence numeric(5,4) check (confidence >= 0 and confidence <= 1),
  evidence jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique(source_asset_id, target_asset_id, relationship_type)
);

create index if not exists security_relationships_org_idx on public.security_asset_relationships(organization_id);

create table if not exists public.security_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  asset_id uuid references public.security_assets(id) on delete set null,
  event_type text not null,
  severity text not null default 'info' check (severity in ('info','low','medium','high','critical')),
  source text not null,
  title text not null,
  description text,
  observed_at timestamptz not null default now(),
  evidence jsonb not null default '{}'::jsonb,
  raw_reference text,
  created_at timestamptz not null default now()
);

create index if not exists security_events_org_time_idx on public.security_events(organization_id, observed_at desc);
create index if not exists security_events_asset_idx on public.security_events(asset_id);

create table if not exists public.security_findings (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  asset_id uuid references public.security_assets(id) on delete set null,
  title text not null,
  finding_type text not null,
  severity text not null default 'medium' check (severity in ('low','medium','high','critical')),
  status text not null default 'open' check (status in ('open','acknowledged','resolved','dismissed')),
  summary text,
  evidence jsonb not null default '{}'::jsonb,
  remediation text,
  detected_at timestamptz not null default now(),
  resolved_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists security_findings_org_status_idx on public.security_findings(organization_id, status);

create table if not exists public.security_integrations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  provider text not null,
  integration_type text not null,
  display_name text not null,
  status text not null default 'pending' check (status in ('pending','connected','degraded','disconnected','error')),
  scopes jsonb not null default '[]'::jsonb,
  configuration jsonb not null default '{}'::jsonb,
  last_sync_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(organization_id, provider, integration_type)
);

create table if not exists public.ai_security_systems (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  asset_id uuid references public.security_assets(id) on delete set null,
  name text not null,
  provider text,
  model text,
  system_type text not null default 'application' check (system_type in ('application','assistant','agent_platform','model','internal','other')),
  environment text not null default 'production',
  data_classification text not null default 'unknown' check (data_classification in ('public','internal','confidential','restricted','unknown')),
  status text not null default 'active' check (status in ('active','inactive','unknown')),
  capabilities jsonb not null default '[]'::jsonb,
  permissions jsonb not null default '{}'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists ai_security_systems_org_idx on public.ai_security_systems(organization_id);

create table if not exists public.ai_security_agents (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  system_id uuid references public.ai_security_systems(id) on delete cascade,
  name text not null,
  purpose text,
  autonomy_level text not null default 'assisted' check (autonomy_level in ('assisted','supervised','autonomous')),
  tools jsonb not null default '[]'::jsonb,
  permissions jsonb not null default '{}'::jsonb,
  data_access jsonb not null default '[]'::jsonb,
  status text not null default 'active' check (status in ('active','inactive','unknown')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists ai_security_agents_org_idx on public.ai_security_agents(organization_id);

create table if not exists public.ai_security_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  system_id uuid references public.ai_security_systems(id) on delete set null,
  agent_id uuid references public.ai_security_agents(id) on delete set null,
  event_type text not null,
  severity text not null default 'info' check (severity in ('info','low','medium','high','critical')),
  title text not null,
  description text,
  observed_at timestamptz not null default now(),
  evidence jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists ai_security_events_org_time_idx on public.ai_security_events(organization_id, observed_at desc);

create table if not exists public.security_actions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  finding_id uuid references public.security_findings(id) on delete set null,
  requested_by uuid references auth.users(id) on delete set null,
  action_type text not null,
  status text not null default 'pending' check (status in ('pending','approved','executing','completed','failed','cancelled')),
  target jsonb not null default '{}'::jsonb,
  authorization jsonb not null default '{}'::jsonb,
  result jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  executed_at timestamptz
);

create index if not exists security_actions_org_time_idx on public.security_actions(organization_id, created_at desc);

alter table public.security_assets enable row level security;
alter table public.security_asset_relationships enable row level security;
alter table public.security_events enable row level security;
alter table public.security_findings enable row level security;
alter table public.security_integrations enable row level security;
alter table public.ai_security_systems enable row level security;
alter table public.ai_security_agents enable row level security;
alter table public.ai_security_events enable row level security;
alter table public.security_actions enable row level security;

-- Access is organization-scoped through the existing profiles table.
drop policy if exists "security_assets_org_access" on public.security_assets;
create policy "security_assets_org_access" on public.security_assets
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));

drop policy if exists "security_relationships_org_access" on public.security_asset_relationships;
create policy "security_relationships_org_access" on public.security_asset_relationships
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));

drop policy if exists "security_events_org_access" on public.security_events;
create policy "security_events_org_access" on public.security_events
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));

drop policy if exists "security_findings_org_access" on public.security_findings;
create policy "security_findings_org_access" on public.security_findings
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));

drop policy if exists "security_integrations_org_access" on public.security_integrations;
create policy "security_integrations_org_access" on public.security_integrations
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));

drop policy if exists "ai_security_systems_org_access" on public.ai_security_systems;
create policy "ai_security_systems_org_access" on public.ai_security_systems
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));

drop policy if exists "ai_security_agents_org_access" on public.ai_security_agents;
create policy "ai_security_agents_org_access" on public.ai_security_agents
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));

drop policy if exists "ai_security_events_org_access" on public.ai_security_events;
create policy "ai_security_events_org_access" on public.ai_security_events
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));

drop policy if exists "security_actions_org_access" on public.security_actions;
create policy "security_actions_org_access" on public.security_actions
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));
