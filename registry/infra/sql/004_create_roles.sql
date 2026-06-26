-- ============================================================
-- 004_create_roles.sql
-- Creates database roles and grants minimum required permissions.
-- Run after 003_create_procedures.sql.
--
-- Three roles:
--   compass_importer  - import script only (stage pending records)
--   compass_reviewer  - security reviewer (approve/reject via procedures)
--   compass_reader    - detection engine (read approved registry only)
-- ============================================================


-- ------------------------------------------------------------
-- ROLE: compass_importer
-- Used by: Python import script
-- Can: INSERT into import_run and pending tables
--      SELECT from approved registry (to check for duplicates)
-- Cannot: INSERT into approved_ai_registry directly
--         Execute approval/rejection procedures
-- ------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'compass_importer' AND type = 'R')
BEGIN
    CREATE ROLE compass_importer;
    PRINT 'Role [compass_importer] created.';
END
GO

GRANT SELECT ON [compass].[approved_ai_registry]    TO compass_importer;
GRANT SELECT ON [compass].[pending_ai_registry]     TO compass_importer;
GRANT INSERT ON [compass].[registry_import_run]     TO compass_importer;
GRANT INSERT ON [compass].[pending_ai_registry]     TO compass_importer;
GRANT EXECUTE ON [compass].[usp_GetApprovedRegistry] TO compass_importer;
GO


-- ------------------------------------------------------------
-- ROLE: compass_reviewer
-- Used by: security reviewer (human or admin UI)
-- Can: View pending items, execute approval/rejection procedures
--      View approved registry
-- Cannot: INSERT directly into any table
--         Bypass the stored procedure approval workflow
-- ------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'compass_reviewer' AND type = 'R')
BEGIN
    CREATE ROLE compass_reviewer;
    PRINT 'Role [compass_reviewer] created.';
END
GO

GRANT SELECT ON [compass].[pending_ai_registry]         TO compass_reviewer;
GRANT SELECT ON [compass].[approved_ai_registry]        TO compass_reviewer;
GRANT SELECT ON [compass].[registry_import_run]         TO compass_reviewer;
GRANT EXECUTE ON [compass].[usp_ApproveRegistryEntry]   TO compass_reviewer;
GRANT EXECUTE ON [compass].[usp_RejectRegistryEntry]    TO compass_reviewer;
GRANT EXECUTE ON [compass].[usp_WatchlistRegistryEntry] TO compass_reviewer;
GRANT EXECUTE ON [compass].[usp_GetPendingItems]        TO compass_reviewer;
GRANT EXECUTE ON [compass].[usp_GetApprovedRegistry]    TO compass_reviewer;
GRANT EXECUTE ON [compass].[usp_DeactivateRegistryEntry] TO compass_reviewer;
GO


-- ------------------------------------------------------------
-- ROLE: compass_reader
-- Used by: Compass detection engine / frontend API
-- Can: SELECT from approved registry only
-- Cannot: modify anything
-- ------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'compass_reader' AND type = 'R')
BEGIN
    CREATE ROLE compass_reader;
    PRINT 'Role [compass_reader] created.';
END
GO

GRANT SELECT ON [compass].[approved_ai_registry]    TO compass_reader;
GRANT EXECUTE ON [compass].[usp_GetApprovedRegistry] TO compass_reader;
GO


-- ------------------------------------------------------------
-- CREATE DATABASE USERS (replace passwords before running)
-- These are the actual login accounts assigned to each role.
--
-- Run these blocks manually after creating SQL logins at the
-- server level in Azure portal or via T-SQL master database.
-- ------------------------------------------------------------

/*
-- Create users and assign roles (run in compass-registry database):

CREATE USER compass_import_user WITH PASSWORD = 'ReplaceWithStrongPassword1!';
ALTER ROLE compass_importer ADD MEMBER compass_import_user;

CREATE USER compass_review_user WITH PASSWORD = 'ReplaceWithStrongPassword2!';
ALTER ROLE compass_reviewer ADD MEMBER compass_review_user;

CREATE USER compass_read_user WITH PASSWORD = 'ReplaceWithStrongPassword3!';
ALTER ROLE compass_reader ADD MEMBER compass_read_user;
*/


PRINT 'All roles and permissions configured successfully.';
GO
