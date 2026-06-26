-- ============================================================
-- 001_create_schema.sql
-- Creates the compass schema namespace in Azure SQL Database.
-- Run this first, against compass-registry database.
-- ============================================================

IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = 'compass')
BEGIN
    EXEC('CREATE SCHEMA compass');
    PRINT 'Schema [compass] created.';
END
ELSE
BEGIN
    PRINT 'Schema [compass] already exists. Skipping.';
END
GO
