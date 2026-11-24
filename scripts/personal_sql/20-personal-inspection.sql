-- Run as the protected local postgres operator after all three revisions.
BEGIN;
DO $guard$
BEGIN
  IF current_database() <> 'clipforge' OR current_user <> 'postgres'
     OR (SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_catalog.pg_database
         WHERE datname = current_database()) IS DISTINCT FROM 'clipforge_migrator' THEN
    RAISE EXCEPTION 'unexpected_database_or_operator';
  END IF;
  IF ARRAY(SELECT revision::text FROM public.auth_schema_migrations ORDER BY revision)
       IS DISTINCT FROM ARRAY['auth01_0001','auth02_0002']::text[]
     OR ARRAY(SELECT revision::text FROM public.cloud_schema_migrations ORDER BY revision)
       IS DISTINCT FROM ARRAY['cloud01_0001']::text[] THEN
    RAISE EXCEPTION 'unexpected_migration_revisions';
  END IF;
END
$guard$;
GRANT CONNECT ON DATABASE clipforge TO aldemaro_int;
CREATE SCHEMA clipforge_inspect AUTHORIZATION clipforge_migrator;
REVOKE ALL ON SCHEMA clipforge_inspect FROM PUBLIC;
GRANT USAGE ON SCHEMA clipforge_inspect TO aldemaro_int;
SET LOCAL ROLE clipforge_migrator;
ALTER DEFAULT PRIVILEGES FOR ROLE clipforge_migrator REVOKE ALL PRIVILEGES ON TABLES FROM aldemaro_int;
ALTER DEFAULT PRIVILEGES FOR ROLE clipforge_migrator IN SCHEMA clipforge_inspect
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, aldemaro_int;

-- These projections omit account identifiers, payload, object locations and tokens.
CREATE VIEW clipforge_inspect.workspaces WITH (security_barrier = true) AS
  SELECT id AS workspace_id, created_at FROM public.auth_workspaces;
CREATE VIEW clipforge_inspect.projects WITH (security_barrier = true) AS
  SELECT id AS project_id, created_at FROM public.auth_projects;
CREATE VIEW clipforge_inspect.documents WITH (security_barrier = true) AS
  SELECT job_id AS project_id, kind, id AS document_id, revision, updated_at
    FROM public.cloud_documents;
CREATE VIEW clipforge_inspect.schema_revisions WITH (security_barrier = true) AS
  SELECT revision, applied_at FROM public.auth_schema_migrations
  UNION ALL
  SELECT revision, applied_at FROM public.cloud_schema_migrations;
GRANT SELECT ON clipforge_inspect.workspaces, clipforge_inspect.projects, clipforge_inspect.documents,
  clipforge_inspect.schema_revisions TO aldemaro_int;
COMMIT;
