-- migrate:up

CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION nuvix_admin;

-- Tables will be created using database lib

-- Gets the User ID from the request cookie
create or replace function auth.uid() returns text as $$
  select nullif(current_setting('request.auth.user.$id', true), '')::text;
$$ language sql stable;

-- Gets the User Roles from the request cookie
create or replace function auth.role() returns text[] as $$
  select nullif(current_setting('request.auth.roles', true), '')::text[];
$$ language sql stable;

-- Gets the User email
create or replace function auth.email() returns text as $$
  select nullif(current_setting('request.auth.user.email', true), '')::text;
$$ language sql stable;

-- usage on auth functions to API roles
GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role;
