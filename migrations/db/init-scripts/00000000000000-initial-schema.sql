-- migrate:up

-- Set up realtime
-- defaults to empty publication
create publication nuvix_realtime;

-- Nuvix super admin
alter user  nuvix_admin with superuser createdb createrole replication bypassrls;

-- Nuvix replication user
create user nuvix_replication_admin with login replication;

-- Extension namespacing
create schema if not exists extensions;
create extension if not exists "uuid-ossp"      with schema extensions;
create extension if not exists pgcrypto         with schema extensions;

-- Set up auth roles for the developer
create role anon                nologin noinherit;
create role authenticated       nologin noinherit; -- "logged in" user: web_user, app_user, etc
create role service_role        nologin noinherit bypassrls; -- allow developers to create JWT's that bypass their policies

grant usage                     on schema public to postgres, service_role;
alter default privileges in schema public grant all on tables to postgres, service_role;
alter default privileges in schema public grant all on functions to postgres, service_role;
alter default privileges in schema public grant all on sequences to postgres, service_role;

-- Allow Extensions to be used in the API
grant usage                     on schema extensions to postgres, service_role;

-- Set up namespacing
alter user nuvix_admin SET search_path TO public, extensions;

-- These are required so that the users receive grants whenever "nuvix_admin" creates tables/function
alter default privileges for user nuvix_admin in schema public grant all
    on sequences to postgres, service_role;
alter default privileges for user nuvix_admin in schema public grant all
    on tables to postgres, service_role;
alter default privileges for user nuvix_admin in schema public grant all
    on functions to postgres, service_role;

-- Set short statement/query timeouts for API roles
alter role anon set statement_timeout = '3s';
alter role authenticated set statement_timeout = '8s';

-- migrate:down
