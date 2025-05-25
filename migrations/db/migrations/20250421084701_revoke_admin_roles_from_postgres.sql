-- migrate:up
revoke all on schema storage from anon, authenticated, service_role, postgres;

revoke all on schema auth from nuvix, postgres;

-- migrate:down
