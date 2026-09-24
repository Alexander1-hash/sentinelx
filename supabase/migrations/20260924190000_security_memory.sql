-- SentinelX Security Memory
create table if not exists public.security_memory (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  memory_type text not null check (memory_type in ('finding_state','investigation','operator_decision','response_outcome','evidence_change')),
  subject_id uuid,
  title text not null,
  summary text not null,
  state text not null default 'active',
  data jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
create index if not exists security_memory_org_time_idx on public.security_memory(organization_id, occurred_at desc);
create index if not exists security_memory_subject_idx on public.security_memory(organization_id, subject_id);
alter table public.security_memory enable row level security;
drop policy if exists "security_memory_org_access" on public.security_memory;
create policy "security_memory_org_access" on public.security_memory
for all to authenticated
using (organization_id = (select organization_id from public.profiles where id = auth.uid()))
with check (organization_id = (select organization_id from public.profiles where id = auth.uid()));
