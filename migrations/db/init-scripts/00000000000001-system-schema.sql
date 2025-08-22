-- migrate:up

-- Create schemas
create schema if not exists system authorization nuvix_admin;
create schema if not exists core authorization nuvix_admin;

-- Schemas metadata table
CREATE TABLE IF NOT EXISTS system.schemas (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    type VARCHAR(20) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    description TEXT,
    metadata JSONB DEFAULT '{}' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Indexes for schemas
CREATE INDEX IF NOT EXISTS schema_name_index ON system.schemas (name);
CREATE INDEX IF NOT EXISTS schema_id_index ON system.schemas (id);
CREATE INDEX IF NOT EXISTS schema_type_index ON system.schemas (type);
CREATE INDEX IF NOT EXISTS schema_enabled_index ON system.schemas (enabled);


-- Tables metadata (managed tables)
CREATE TABLE IF NOT EXISTS system.tables (
    id BIGSERIAL PRIMARY KEY,
    oid OID NOT NULL UNIQUE,                     -- Postgres table OID
    name TEXT NOT NULL,                          -- Current name of the table
    perms_oid OID,                               -- OID of related _perms table
    schema_id BIGINT NOT NULL REFERENCES system.schemas(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Indexes for tables
CREATE UNIQUE INDEX idx_tables_oid ON system.tables (oid);
CREATE INDEX idx_tables_schema_id ON system.tables (schema_id);
CREATE INDEX idx_tables_name_schema_id ON system.tables (name, schema_id);

alter user nuvix_admin SET search_path TO system, core, auth, extensions;

-- Create functions 

CREATE OR REPLACE FUNCTION system.is_managed_schema(schema_name text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = system, pg_catalog
AS $$
DECLARE
    schema_exists boolean;
BEGIN
    -- Check if the schema exists and is of type 'managed'
    SELECT EXISTS (
        SELECT 1 FROM system.schemas
        WHERE name = schema_name AND type = 'managed'
    ) INTO schema_exists;
    RETURN schema_exists;
END;
$$;

-- System helper: apply baseline API grants to a schema
CREATE OR REPLACE FUNCTION system.apply_schema_grants(target_schema text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = system, pg_catalog
AS $$
BEGIN
  -- Allow runtime roles to see objects
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO anon, authenticated, postgres', target_schema);

  -- Existing objects
  EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO anon, authenticated', target_schema);
  EXECUTE format('GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO authenticated', target_schema);
  EXECUTE format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %I TO anon, authenticated', target_schema);
  EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO anon, authenticated', target_schema);

  -- Future objects
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO anon, authenticated', target_schema);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT INSERT, UPDATE, DELETE ON TABLES TO authenticated', target_schema);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT EXECUTE ON FUNCTIONS TO anon, authenticated', target_schema);
  EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES TO anon, authenticated', target_schema);
END;
$$;

-- System helper: when create table on managed schema
CREATE OR REPLACE FUNCTION system.on_managed_table_create()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = system, pg_catalog
AS $$
DECLARE
  cmd record;
  sname text;
  tname text;
  is_managed boolean;
  has_id boolean;
  is_bigint boolean;
  tbl_oid oid;
  perms_oid oid;
  schema_id bigint;
BEGIN
  FOR cmd IN
    SELECT * FROM pg_event_trigger_ddl_commands()
    WHERE command_tag = 'CREATE TABLE' AND object_type = 'table'
  LOOP
    sname := cmd.schema_name;
    tname := split_part(cmd.object_identity, '.', 2);

    -- Skip internal/system schemas and perms tables
    CONTINUE WHEN tname LIKE '%_perms'
           OR sname LIKE 'pg_%'
           OR sname IN ('information_schema', 'system', 'extensions');

    -- Only act for managed schemas
    SELECT system.is_managed_schema(sname) INTO is_managed;
    IF NOT is_managed THEN
      CONTINUE;
    END IF;

    -- Get schema_id for linking
    SELECT id INTO schema_id
    FROM system.schemas
    WHERE name = sname;

    -- Check for _id presence and type
    SELECT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = sname AND table_name = tname AND column_name = '_id'
    ) INTO has_id;

    IF has_id THEN
      SELECT (data_type = 'bigint')
      FROM information_schema.columns
      WHERE table_schema = sname AND table_name = tname AND column_name = '_id'
      INTO is_bigint;
    ELSE
      is_bigint := false;
    END IF;

    -- Add _id if absent or wrong type
    IF NOT has_id OR NOT is_bigint THEN
      PERFORM set_config('system.is_managed_table_create', 'true', true);
      EXECUTE format(
        'ALTER TABLE %I.%I ADD COLUMN IF NOT EXISTS _id BIGINT GENERATED BY DEFAULT AS IDENTITY',
        sname, tname
      );
      EXECUTE format(
        'CREATE UNIQUE INDEX IF NOT EXISTS %I ON %I.%I(_id)',
        tname || '_id_key', sname, tname
      );
      PERFORM set_config('system.is_managed_table_create', 'false', true);
    END IF;

    -- Create <table>_perms if not exists
    PERFORM set_config('system.skip_perms_check', 'true', true);
    EXECUTE format(
      'CREATE TABLE IF NOT EXISTS %I.%I_perms (
         id BIGSERIAL PRIMARY KEY,
         roles TEXT[] NOT NULL,
         permission TEXT NOT NULL,
         row_id BIGINT DEFAULT NULL,
         extra JSONB DEFAULT NULL,
         created_at TIMESTAMPTZ DEFAULT NOW(),
         updated_at TIMESTAMPTZ DEFAULT NOW(),
         CONSTRAINT chk_permission CHECK (permission IN (''create'',''read'',''update'',''delete''))
       )',
      sname, tname
    );
    PERFORM set_config('system.skip_perms_check', 'false', true);

    EXECUTE format(
      'CREATE INDEX IF NOT EXISTS %I_perms_roles_gin_idx ON %I.%I_perms USING GIN (roles)',
      tname, sname, tname
    );
    EXECUTE format(
      'CREATE INDEX IF NOT EXISTS %I_perms_perm_row_idx ON %I.%I_perms (permission, row_id)',
      tname, sname, tname
    );

    EXECUTE format(
      'COMMENT ON TABLE %I.%I_perms IS %L',
      sname, tname, 'Permission system for ' || sname || '.' || tname
    );

    -- Lookup OIDs
    SELECT c.oid INTO tbl_oid
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = sname AND c.relname = tname;

    SELECT c.oid INTO perms_oid
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = sname AND c.relname = tname || '_perms';

    -- Insert into system.tables metadata
    INSERT INTO system.tables (oid, name, perms_oid, schema_id)
    VALUES (tbl_oid, tname, perms_oid, schema_id)
    ON CONFLICT (oid) DO UPDATE
      SET name = EXCLUDED.name,
          perms_oid = EXCLUDED.perms_oid,
          schema_id = EXCLUDED.schema_id,
          updated_at = NOW();
  END LOOP;
END;
$$;

DROP EVENT TRIGGER IF EXISTS nuvix_on_managed_table_create;
CREATE EVENT TRIGGER nuvix_on_managed_table_create
  ON ddl_command_end
  WHEN TAG IN ('CREATE TABLE')
  EXECUTE PROCEDURE system.on_managed_table_create();

-- System helper: when alter table on managed schema
CREATE OR REPLACE FUNCTION SYSTEM.ON_MANAGED_TABLE_ALTER () 
RETURNS EVENT_TRIGGER
SECURITY DEFINER
SET search_path = system, pg_catalog
 AS $$
DECLARE
    r RECORD;
    schema_info RECORD;
    table_info RECORD;
    old_table_name text;
    new_table_name text;
    is_rename_operation boolean;
	is_rename_table boolean;
	is_rename_column boolean;
    current_sql text;
	normalized_sql text;
    schema_type text;
    is_perms_table boolean := false;
    base_table_name text;
    has_id_column boolean;
BEGIN
    current_sql := current_query();
	normalized_sql := regexp_replace(current_sql, '/\*.*?\*/', '', 'gs');
	normalized_sql := regexp_replace(normalized_sql, '--.*$', '', 'gm');
	normalized_sql := regexp_replace(normalized_sql, '''([^'']|'''')*''', '', 'g');
	normalized_sql := regexp_replace(normalized_sql, '[[:space:]]+', ' ', 'g');
	normalized_sql := trim(normalized_sql);
	
	is_rename_table := normalized_sql ~*    '^ALTER\s+TABLE(?:\s+IF\s+EXISTS)?\s+(?:\S+\.)?\S+\s+RENAME\s+TO\s+\S+';
	is_rename_column := normalized_sql ~* '^ALTER\s+TABLE(?:\s+IF\s+EXISTS)?\s+(?:\S+\.)?\S+\s+RENAME\s+TO\s+\S+';
	is_rename_operation := is_rename_table OR is_rename_column;
	
    FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() 
    WHERE command_tag = 'ALTER TABLE'
    LOOP
        -- Check if schema is managed
        SELECT s.type INTO schema_type
        FROM system.schemas s
        WHERE s.name = r.schema_name 
        AND s.enabled = true;

        -- Skip if schema is not managed or not found
        IF NOT FOUND OR schema_type != 'managed' THEN
            CONTINUE;
        END IF;

        -- Get the new table name from the object identity
        new_table_name := split_part(r.object_identity, '.', 2);

        -- Check if this is a _perms table by looking for base table reference
        SELECT t.*, s.type as schema_type INTO table_info
        FROM system.tables t
        JOIN system.schemas s ON t.schema_id = s.id
        WHERE t.perms_oid = r.objid;

        IF FOUND THEN
            -- This is a _perms table being altered
            is_perms_table := true;
            base_table_name := table_info.name;
        ELSE
            -- Check if it's a base table
            SELECT t.*, s.type as schema_type INTO table_info
            FROM system.tables t
            JOIN system.schemas s ON t.schema_id = s.id
            WHERE t.oid = r.objid;
            
            -- Skip if table not found in system.tables
            IF NOT FOUND THEN
                CONTINUE;
            END IF;
            is_perms_table := false;
        END IF;

        -- STEP 1: Handle RENAME operations
        IF is_rename_table THEN
            -- Case 1: Someone is trying to rename a _perms table directly
            IF is_perms_table THEN
                -- Always revert perms table renames - they should follow base table
				IF new_table_name = table_info.name || '_perms' THEN
			CONTINUE;
				END IF;
                RAISE EXCEPTION 
                    'Permission denied: Cannot rename _perms table %.% directly. '
                    'Rename the main table %.% instead.',
                    r.schema_name, new_table_name,
                    r.schema_name, base_table_name;
            
            -- Case 2: Normal base table rename
            ELSE
                old_table_name := table_info.name;
                
                -- Check if names are different (actual rename occurred)
                IF old_table_name != new_table_name THEN
					IF new_table_name ILIKE '%_perms' THEN 
					RAISE EXCEPTION 'Cannot use `_perms` suffix for tables in managed schema.';
					END IF;
					
                    -- Update the table name in metadata
                    UPDATE system.tables 
                    SET name = new_table_name, 
                        updated_at = now()
                    WHERE oid = r.objid;
                    
                    -- Rename the associated _perms table if it exists
                    IF table_info.perms_oid IS NOT NULL THEN
                        EXECUTE format(
                            'ALTER TABLE %I.%I RENAME TO %I',
                            r.schema_name,
                            old_table_name || '_perms',
                            new_table_name || '_perms'
                        );
                    END IF;
                END IF;
            END IF;
        END IF;

        -- STEP 2: Block _id column alterations (only for base tables)
       -- STEP 2: Block altering _id columns in managed tables
	IF NOT is_perms_table THEN
    -- Match DROP/ALTER/TYPE applied specifically to _id column
		IF current_sql ~*
		'_id' AND ( current_sql ~* 'DROP COLUMN' OR current_sql ~* 'ALTER COLUMN' OR current_sql ~* 'TYPE.*_id' OR current_sql ~* '_id.*TYPE' ) THEN RAISE EXCEPTION 'Permission denied: Cannot alter _id columns in managed table %.%', r.schema_name, table_info.name; END IF;

    -- Block renaming of _id columns
    IF is_rename_column THEN 
        SELECT EXISTS (
            SELECT 1 
            FROM pg_attribute attr
            JOIN pg_class cls ON cls.oid = attr.attrelid
            JOIN pg_namespace nsp ON nsp.oid = cls.relnamespace
            WHERE nsp.nspname = r.schema_name
              AND cls.oid = r.objid
              AND attr.attname = '_id'
        ) INTO has_id_column;

        IF has_id_column THEN
            RAISE EXCEPTION 
                'Permission denied: Cannot rename _id column in managed table %.%',
                r.schema_name, table_info.name;
        END IF;
    END IF;
END IF;

-- STEP 3: Block direct alterations to _perms tables
-- Allow only RENAME TABLE, but block renames of columns too
IF is_perms_table THEN
    IF NOT is_rename_operation OR current_sql ~* '\bRENAME\s+COLUMN\b' THEN
        RAISE EXCEPTION 
            'Permission denied: Cannot directly alter _perms table %.%.',
            r.schema_name, new_table_name;
    END IF;
END IF;

        -- Additional protection: Block alterations if table is in system schema
        IF schema_type = 'system' AND current_user != 'nuvix_admin' THEN
            RAISE EXCEPTION 
                'Permission denied: Cannot alter system table %.%. '
                'Only nuvix_admin can perform this operation.',
                r.schema_name, table_info.name;
        END IF;

    END LOOP;
END;
$$ LANGUAGE PLPGSQL;

DROP EVENT TRIGGER IF EXISTS ON_MANAGED_TABLE_ALTER;

CREATE EVENT TRIGGER ON_MANAGED_TABLE_ALTER ON DDL_COMMAND_END WHEN TAG IN ('ALTER TABLE')
EXECUTE FUNCTION SYSTEM.ON_MANAGED_TABLE_ALTER ();

-- System helper: when drop table on managed schema
CREATE OR REPLACE FUNCTION SYSTEM.ON_MANAGED_TABLE_DROP () 
RETURNS EVENT_TRIGGER 
SECURITY DEFINER
SET search_path = system, pg_catalog
AS $$
DECLARE
    r RECORD;
    schema_info RECORD;
    table_info RECORD;
    base_table_info RECORD;
    schema_type text;
    is_perms_table boolean := false;
    base_table_oid oid;
BEGIN
    FOR r IN SELECT * FROM pg_event_trigger_dropped_objects() 
    WHERE object_type = 'table'
    LOOP
        -- Check if schema is managed
        SELECT s.type INTO schema_type
        FROM system.schemas s
        WHERE s.name = r.schema_name 
        AND s.enabled = true;

        -- Skip if schema is not managed or not found
        IF NOT FOUND OR schema_type != 'managed' THEN
            CONTINUE;
        END IF;

        -- Check if this is a _perms table by looking for base table reference
        SELECT t.* INTO table_info
        FROM system.tables t
        JOIN system.schemas s ON t.schema_id = s.id
        WHERE t.perms_oid = r.objid;

        IF FOUND THEN
            -- This is a _perms table being dropped
            is_perms_table := true;
            base_table_oid := table_info.oid;
        ELSE
            -- Check if it's a base table
            SELECT t.* INTO table_info
            FROM system.tables t
            JOIN system.schemas s ON t.schema_id = s.id
            WHERE t.oid = r.objid;
            
            -- Skip if table not found in system.tables
            IF NOT FOUND THEN
                CONTINUE;
            END IF;
            is_perms_table := false;
        END IF;

        -- Case 1: Someone is trying to drop a _perms table directly
        IF is_perms_table THEN
            RAISE EXCEPTION 
                'Permission denied: Cannot drop _perms table %.% directly. '
                'Drop the main table %.% instead.',
                r.schema_name, r.object_name,
                r.schema_name, table_info.name;
        
        -- Case 2: Base table is being dropped
        ELSE
            -- First, drop the associated _perms table if it exists
			DELETE FROM system.tables 
            WHERE oid = r.objid;
			
            IF table_info.perms_oid IS NOT NULL THEN
                -- Check if the perms table still exists
                IF EXISTS (
                    SELECT 1 FROM pg_class 
                    WHERE oid = table_info.perms_oid
                ) THEN
                    EXECUTE format(
                        'DROP TABLE IF EXISTS %I.%I',
                        r.schema_name,
                        table_info.name || '_perms'
                    );
                END IF;
            END IF;           
        END IF;

        -- Additional protection: Block drops if table is in system schema
        IF schema_type = 'system' AND current_user != 'nuvix_admin' THEN
            RAISE EXCEPTION 
                'Permission denied: Cannot drop system table %.%. '
                'Only nuvix_admin can perform this operation.',
                r.schema_name, table_info.name;
        END IF;

    END LOOP;
END;
$$ LANGUAGE PLPGSQL;

-- Create the event trigger for DROP operations
DROP EVENT TRIGGER IF EXISTS ON_MANAGED_TABLE_DROP;

CREATE EVENT TRIGGER ON_MANAGED_TABLE_DROP ON SQL_DROP
EXECUTE FUNCTION SYSTEM.ON_MANAGED_TABLE_DROP ();


-- System helper: block _perms table/view creation in managed schemas
CREATE OR REPLACE FUNCTION SYSTEM.BLOCK_PERMS_CREATION() 
RETURNS EVENT_TRIGGER
AS $$
DECLARE
    r RECORD;
    schema_info RECORD;
    schema_type text;
    object_name text;
    object_type text;
    is_system_operation boolean;
    current_role_name text;
BEGIN
    -- Get current role and check system flags
    current_role_name := current_user;
    is_system_operation := COALESCE(current_setting('system.skip_perms_check', true) = 'true', false);
    
    -- Allow system operations and nuvix_migrate role to bypass
    IF is_system_operation OR current_role_name = 'nuvix_migrate' OR current_role_name = 'nuvix_admin' THEN
        RAISE NOTICE 'System operation detected: skipping _perms creation check';
        RETURN;
    END IF;

    FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() 
    WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'CREATE VIEW', 'CREATE MATERIALIZED VIEW')
    LOOP
        -- Get object name and type
        object_name := split_part(r.object_identity, '.', 2);
        object_type := LOWER(r.object_type);
        
        -- Skip if not a _perms object
        IF object_name NOT LIKE '%\_perms' THEN
            CONTINUE;
        END IF;

        -- Check if schema is managed
        SELECT s.type INTO schema_type
        FROM system.schemas s
        WHERE s.name = r.schema_name 
        AND s.enabled = true;

        -- Skip if schema is not managed or not found
        IF NOT FOUND OR schema_type != 'managed' THEN
            CONTINUE;
        END IF;

        -- Block _perms object creation in managed schemas
        RAISE EXCEPTION 
            'Permission denied: Cannot create _perms % "%" in managed schema "%". '
            '_perms objects are automatically managed by the system.',
            object_type, object_name, r.schema_name;

    END LOOP;
END;
$$ LANGUAGE PLPGSQL;

-- Create the event trigger for CREATE operations
DROP EVENT TRIGGER IF EXISTS BLOCK_PERMS_CREATION;
CREATE EVENT TRIGGER BLOCK_PERMS_CREATION 
ON ddl_command_end
WHEN TAG IN ('CREATE TABLE', 'CREATE VIEW')
EXECUTE FUNCTION SYSTEM.BLOCK_PERMS_CREATION();
