-- SentinelX atomic response outcome recording
-- Keeps security_actions and security_memory consistent when recording an explicit executor result.

create or replace function public.record_security_action_outcome(
  p_action_id uuid,
  p_status text,
  p_executor_type text,
  p_execution_reference text,
  p_evidence jsonb,
  p_result jsonb default '{}'::jsonb
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
  v_outcome jsonb;
  v_memory public.security_memory%rowtype;
begin
  if v_user_id is null then
    raise exception using errcode = '42501', message = 'Authentication is required.';
  end if;

  if p_status not in ('completed', 'failed') then
    raise exception using errcode = '22023', message = 'Outcome status must be completed or failed.';
  end if;

  if nullif(trim(p_executor_type), '') is null
     or nullif(trim(p_execution_reference), '') is null then
    raise exception using errcode = '22023', message = 'Executor type and execution reference are required.';
  end if;

  if jsonb_typeof(coalesce(p_evidence, '[]'::jsonb)) <> 'array'
     or jsonb_array_length(coalesce(p_evidence, '[]'::jsonb)) = 0 then
    raise exception using errcode = '22023', message = 'At least one explicit evidence record is required.';
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

  if v_action.status <> 'approved' then
    raise exception using errcode = '55000', message = 'Only explicitly approved actions can receive an execution outcome.';
  end if;

  v_outcome := coalesce(p_result, '{}'::jsonb)
    || jsonb_build_object(
      'state', p_status,
      'executor_type', trim(p_executor_type),
      'execution_reference', trim(p_execution_reference),
      'evidence', p_evidence,
      'supplied_at', now(),
      'supplied_by', v_user_id,
      'boundary', 'This outcome is recorded from an explicit executor result. SentinelX does not infer execution from approval alone.'
    );

  update public.security_actions
  set
    status = p_status,
    result = coalesce(v_action.result, '{}'::jsonb)
      || jsonb_build_object(
        'state', p_status,
        'response_outcome', v_outcome
      ),
    executed_at = now()
  where id = p_action_id
    and organization_id = v_organization_id
  returning * into v_action;

  insert into public.security_memory (
    organization_id,
    memory_type,
    subject_id,
    title,
    summary,
    state,
    data
  )
  values (
    v_organization_id,
    'response_outcome',
    v_action.id,
    case
      when p_status = 'completed' then 'Security action execution completed'
      else 'Security action execution failed'
    end,
    case
      when p_status = 'completed'
        then v_action.action_type || ' received a completed result from ' || trim(p_executor_type) || '.'
      else v_action.action_type || ' received a failed result from ' || trim(p_executor_type) || '.'
    end,
    p_status,
    jsonb_build_object(
      'action_id', v_action.id,
      'finding_id', v_action.finding_id,
      'action_type', v_action.action_type,
      'status', p_status,
      'executor_type', trim(p_executor_type),
      'execution_reference', trim(p_execution_reference),
      'evidence', p_evidence,
      'response_outcome', v_outcome,
      'memory_reason', 'Created only from an explicit authorized executor result; approval alone is not execution.'
    )
  )
  returning * into v_memory;

  return jsonb_build_object(
    'action', to_jsonb(v_action),
    'memory', to_jsonb(v_memory)
  );
end;
$$;

revoke all on function public.record_security_action_outcome(uuid, text, text, text, jsonb, jsonb) from public;
grant execute on function public.record_security_action_outcome(uuid, text, text, text, jsonb, jsonb) to authenticated;
