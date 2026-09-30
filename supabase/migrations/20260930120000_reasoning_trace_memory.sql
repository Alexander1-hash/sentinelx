-- Trinorin: persist inspectable reasoning traces in the existing security memory timeline.
alter table public.security_memory
  drop constraint if exists security_memory_memory_type_check;

alter table public.security_memory
  add constraint security_memory_memory_type_check
  check (
    memory_type in (
      'finding_state',
      'investigation',
      'operator_decision',
      'response_outcome',
      'evidence_change',
      'verification',
      'reasoning_trace'
    )
  );

create index if not exists security_memory_reasoning_trace_idx
  on public.security_memory(organization_id, memory_type, occurred_at desc);
