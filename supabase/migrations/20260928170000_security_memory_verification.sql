-- Trinorin: extend the existing security_memory timeline with verification records.
-- This does not create another memory store; verification remains a security_memory record.

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
      'verification'
    )
  );
