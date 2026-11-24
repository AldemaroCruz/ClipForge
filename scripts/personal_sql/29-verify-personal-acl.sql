-- Run in the transaction that enables the login. Never return password verifiers.
DO $guard$
BEGIN
  IF current_user <> 'postgres' OR current_database() <> 'clipforge'
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'aldemaro_int'
          AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb
          AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls)
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members
                WHERE member = 'aldemaro_int'::regrole OR roleid = 'aldemaro_int'::regrole)
     OR NOT has_database_privilege('aldemaro_int', current_database(), 'CONNECT')
     OR has_database_privilege('aldemaro_int', current_database(), 'CREATE, TEMPORARY')
     OR NOT has_schema_privilege('aldemaro_int', 'clipforge_inspect', 'USAGE')
     OR has_schema_privilege('aldemaro_int', 'clipforge_inspect', 'CREATE')
     OR has_schema_privilege('aldemaro_int', 'public', 'CREATE') THEN
    RAISE EXCEPTION 'unexpected_personal_role_or_namespace_acl';
  END IF;

  IF ARRAY(
       SELECT c.relname::text FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='clipforge_inspect' AND c.relkind='v'
         AND pg_catalog.pg_get_userbyid(c.relowner)='clipforge_migrator'
         AND has_table_privilege('aldemaro_int', c.oid, 'SELECT')
       ORDER BY c.relname
     ) IS DISTINCT FROM ARRAY['documents','projects','schema_revisions','workspaces']::text[] THEN
    RAISE EXCEPTION 'unexpected_inspection_views';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname IN ('public','clipforge_inspect')
      AND c.relkind IN ('r','p','v','m','f')
      AND (
        has_table_privilege('aldemaro_int', c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
        OR has_any_column_privilege('aldemaro_int', c.oid, 'INSERT,UPDATE,REFERENCES')
        OR ((n.nspname <> 'clipforge_inspect' OR c.relname NOT IN ('documents','projects','schema_revisions','workspaces'))
            AND has_any_column_privilege('aldemaro_int', c.oid, 'SELECT'))
      )
  ) THEN
    RAISE EXCEPTION 'unexpected_personal_table_or_column_acl';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE CASE WHEN n.nspname IN ('public','clipforge_inspect') AND c.relkind = 'S'
               THEN has_sequence_privilege('aldemaro_int', c.oid, 'SELECT,UPDATE,USAGE') ELSE false END
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname IN ('public','clipforge_inspect')
      AND has_function_privilege('aldemaro_int', p.oid, 'EXECUTE')
  ) THEN
    RAISE EXCEPTION 'unexpected_personal_sequence_or_function_acl';
  END IF;
END
$guard$;
