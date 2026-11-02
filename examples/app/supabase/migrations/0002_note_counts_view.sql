-- A per-company count for the backend's dashboard. A view runs with its
-- owner's rights unless it is security_invoker, and new views are granted to
-- anon and authenticated by default, so both lines below are required.
create view public.app_note_counts with (security_invoker = true) as
    select company_id, count(*) as notes from public.app_notes group by company_id;

revoke all on public.app_note_counts from anon, authenticated;
