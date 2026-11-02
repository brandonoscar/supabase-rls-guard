-- Tenancy: companies, who belongs to them, and one company-scoped table.

create table if not exists public.companies (
    id   uuid primary key default gen_random_uuid(),
    name text not null
);

create table if not exists public.company_users (
    company_id uuid not null references public.companies (id),
    user_id    uuid not null,
    primary key (company_id, user_id)
);

create table if not exists public.app_notes (
    id         uuid primary key default gen_random_uuid(),
    company_id uuid not null references public.companies (id),
    body       text not null,
    created_at timestamptz not null default now()
);

alter table public.companies enable row level security;
alter table public.company_users enable row level security;
alter table public.app_notes enable row level security;

create policy "members read their company" on public.companies
    for select using (
        exists (select 1 from public.company_users cu
                 where cu.company_id = companies.id and cu.user_id = auth.uid())
    );

create policy "members read their memberships" on public.company_users
    for select using (user_id = auth.uid());

create policy "members read their company's notes" on public.app_notes
    for select using (
        exists (select 1 from public.company_users cu
                 where cu.company_id = app_notes.company_id and cu.user_id = auth.uid())
    );

create policy "members add notes to their company" on public.app_notes
    for insert with check (
        exists (select 1 from public.company_users cu
                 where cu.company_id = app_notes.company_id and cu.user_id = auth.uid())
    );

grant select on public.companies, public.company_users to authenticated;
grant select, insert on public.app_notes to authenticated;
