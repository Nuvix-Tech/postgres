-- migrate:up
alter role nuvix_admin set log_statement = none;
alter role nuvix_admin set log_statement = none;
-- alter role supabase_storage_admin set log_statement = none;

-- migrate:down
