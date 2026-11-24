-- First disable authentication and invalidate the personal verifier.
-- Run after observing that the target role has the reviewed identity.
BEGIN;
ALTER ROLE aldemaro_int NOLOGIN PASSWORD NULL;
REVOKE SELECT ON clipforge_inspect.workspaces, clipforge_inspect.projects, clipforge_inspect.documents,
  clipforge_inspect.schema_revisions FROM aldemaro_int;
REVOKE USAGE ON SCHEMA clipforge_inspect FROM aldemaro_int;
REVOKE CONNECT ON DATABASE clipforge FROM aldemaro_int;
COMMIT;
SELECT coalesce(bool_and(pg_catalog.pg_terminate_backend(pid)), true) AS own_role_sessions_closed
FROM pg_catalog.pg_stat_activity
WHERE usename = 'aldemaro_int' AND datname = 'clipforge' AND pid <> pg_catalog.pg_backend_pid();
