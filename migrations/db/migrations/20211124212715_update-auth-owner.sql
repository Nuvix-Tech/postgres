-- migrate:up

-- update owner for auth.uid, auth.role and auth.email functions
DO $$
BEGIN
    ALTER FUNCTION auth.uid owner to nuvix_admin;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'Error encountered when changing owner of auth.uid to nuvix_admin';
END $$;

DO $$
BEGIN
    ALTER FUNCTION auth.role owner to nuvix_admin;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'Error encountered when changing owner of auth.role to nuvix_admin';
END $$;

DO $$
BEGIN
    ALTER FUNCTION auth.email owner to nuvix_admin;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'Error encountered when changing owner of auth.email to nuvix_admin';
END $$;
-- migrate:down
