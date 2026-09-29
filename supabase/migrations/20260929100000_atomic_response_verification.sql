-- Trinorin: atomically record post-response verification in the existing security memory timeline.
-- Keeps the security action verification snapshot and verification memory record consistent.

create or replace function public.record_security_action_verification(
  p_action_id uuid,
  p_state text,
  p_summary text,
  p_evidence jsonb,
  p_verification jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_organization_id uuid;
  v_action public.security_actions%rowtype;
  v_memory public.security_memory%rowtype;
  v_verification jsonb;
begin
  if v_user_id is null then
    raise exception using errcode = '42501', message = 'Authentication is required.';
  end if;

  if p_state not in ('resolved', 'persisting', 'returned', 'unknown') then
    raise exception using errcode = '22023', message = 'Verification state is invalid.';
  end if;

  if nullif(trim(p_summary), '') is null then
    raise exception using errcode = '22023', message = 'Verification summary is required.';
  end if;

  if jsonb_typeof(coalesce(p_evidence, '[]'::jsonb)) <> 'array'
     or jsonb_array_length(coalesce(p_evidence, '[]'::jsonb)) = 0 then
    raise exception using errcode = '22023', message = 'At least one explicit verification evidence record is required.';
  end if;

  select organization_id
    into v_organization_id
  from public.profiles
  where id = v_user_id
  limit 1;

  if v_organization_id is null then
    raise exception using errcode = '42501', message = 'Organization is required.';
  end if;

  select *
    into v_action
  from public.security_actions
  where id = p_action_id
    and organization_id = v_organization_id
  for update;

  if not found then
    raise exception using errcode = 'P0002', message = 'Security action not found.';
  end if;

  if v_action.status not in ('completed', 'failed') then
    raise exception using errcode = '55000', message = 'Verification is available only after an explicit completed or failed execution outcome.';
  end if;

  v_verification := coalesce(p_verification, '{}'::jsonb)
    || jsonb_build_object(
      'state', p_state,
      'summary', trim(p_summary),
      'evidence', p_evidence,
      'verified_at', now(),
      'verified_by', v_user_id,
      'action_id', v_action.id,
      'finding_id', v_action.finding_id,
      'boundary', 'Verification records explicit post-response evidence. Resolution is never inferred from missing telemetry.'
    );

  update public.security_actions
  set result = coalesce(v_action.result, '{}'::jsonb)
      || jsonb_build_object('verification', v_verification)
  where id = v_action.id
    and organization_id = v_organization_id
  returning * into v_action;

  insert into public.security_memory (
    organization_id,
    memory_type,
    subject_id,
    title,
    summary,
    state,
    data,
    occurred_at
  )
  values (
    v_organization_id,
    'verification',
    v_action.id,
    case
      when p_state = 'resolved' then 'Security response verified as resolved'
      when p_state = 'persisting' then 'Security condition verified as persisting'
      when p_state = 'returned' then 'Security condition verified as returned'
      else 'Security response verification recorded'
    end,
    trim(p_summary),
    p_state,
    jsonb_build_object(
      'action_id', v_action.id,
      'finding_id', v_action.finding_id,
      'action_type', v_action.action_type,
      'state', p_state,
      'evidence', p_evidence,
      'verification', v_verification,
      'memory_reason', 'Created from explicit post-response verification evidence; it is part of the existing security_memory timeline.'
    ),
    now()
  )
  returning * into v_memory;

  return jsonb_build_object(
    'action', to_jsonb(v_action),
    'memory', to_jsonb(v_memory),
    'verification', v_verification
  );
end;
$$;

revoke all on function public.record_security_action_verification(uuid, text, text, jsonb, jsonb) from public;
grant execute on function public.record_security_action_verification(uuid, text, text, jsonb, jsonb) to authenticated;
