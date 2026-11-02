-- rls-guard: never-applied
-- Kept for history: superseded by 0001 before it ever ran. The directive on
-- the first line makes rls-guard skip this file, because a migration that
-- never ran proves nothing about the database.
create table notes_draft (id serial primary key, body text);
