-- ============================================================
-- 002_create_tables.sql
-- Creates the three core ledger-backed registry tables.
-- Run after 001_create_schema.sql.
--
-- Tables:
--   compass.registry_import_run   - append-only ledger (no updates allowed)
--   compass.pending_ai_registry   - updatable ledger with system versioning
--   compass.approved_ai_registry  - updatable ledger with system versioning
-- ============================================================


-- ------------------------------------------------------------
-- TABLE 1: registry_import_run
-- Records each time the import script checks Microsoft Purview.
-- Append-only: rows can never be updated or deleted.
-- This syntax works without system versioning columns.
-- ------------------------------------------------------------
IF NOT EXISTS (
    SELECT 1 FROM sys.tables t
    JOIN sys.schemas s ON t.schema_id = s.schema_id
    WHERE s.name = 'compass' AND t.name = 'registry_import_run'
)
BEGIN
    CREATE TABLE [compass].[registry_import_run] (
        id                  INT             IDENTITY(1,1)   NOT NULL,
        source_name         NVARCHAR(100)                   NOT NULL,
        source_url          NVARCHAR(500)                   NOT NULL,
        source_hash         NVARCHAR(64)                    NOT NULL,
        domains_found       INT                             NOT NULL DEFAULT 0,
        domains_staged      INT                             NOT NULL DEFAULT 0,
        domains_skipped     INT                             NOT NULL DEFAULT 0,
        imported_by         NVARCHAR(200)                   NOT NULL DEFAULT 'system',
        imported_at         DATETIME2                       NOT NULL DEFAULT GETUTCDATE(),
        notes               NVARCHAR(1000)                  NULL,

        CONSTRAINT PK_registry_import_run PRIMARY KEY (id)
    )
    WITH (LEDGER = ON (APPEND_ONLY = ON));

    PRINT 'Table [compass].[registry_import_run] created (append-only ledger).';
END
ELSE
    PRINT 'Table [compass].[registry_import_run] already exists. Skipping.';
GO


-- ------------------------------------------------------------
-- TABLE 2: pending_ai_registry
-- Staging area for new or changed domains before approval.
-- Updatable ledger requires SYSTEM_VERSIONING = ON and
-- explicit temporal (ValidFrom/ValidTo) columns.
-- ------------------------------------------------------------
IF NOT EXISTS (
    SELECT 1 FROM sys.tables t
    JOIN sys.schemas s ON t.schema_id = s.schema_id
    WHERE s.name = 'compass' AND t.name = 'pending_ai_registry'
)
BEGIN
    CREATE TABLE [compass].[pending_ai_registry] (
        id                      INT             IDENTITY(1,1)   NOT NULL,
        domain_pattern          NVARCHAR(255)                   NOT NULL,
        normalized_domain       NVARCHAR(255)                   NOT NULL,
        source_name             NVARCHAR(100)                   NOT NULL,
        change_type             NVARCHAR(50)                    NOT NULL,
        suggested_tool_name     NVARCHAR(200)                   NULL,
        suggested_category      NVARCHAR(100)                   NULL,
        suggested_risk_level    NVARCHAR(50)                    NULL,
        review_status           NVARCHAR(50)                    NOT NULL DEFAULT 'Pending',
        reviewer_notes          NVARCHAR(2000)                  NULL,
        import_run_id           INT                             NULL,
        requested_at            DATETIME2                       NOT NULL DEFAULT GETUTCDATE(),
        reviewer_name           NVARCHAR(200)                   NULL,
        reviewed_at             DATETIME2                       NULL,

        -- Unknown AI usage fields (from network log discovery)
        first_seen              DATETIME2                       NULL,
        last_seen               DATETIME2                       NULL,
        user_count              INT                             NULL DEFAULT 0,
        request_count           INT                             NULL DEFAULT 0,
        data_uploads_observed   BIT                             NULL DEFAULT 0,
        log_source              NVARCHAR(100)                   NULL,

        -- Required for updatable ledger: system versioning period columns
        -- These are hidden and managed automatically by Azure SQL
        ValidFrom   DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL,
        ValidTo     DATETIME2 GENERATED ALWAYS AS ROW END   HIDDEN NOT NULL,
        PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo),

        CONSTRAINT PK_pending_ai_registry   PRIMARY KEY (id),
        CONSTRAINT CK_pending_review_status CHECK (review_status IN (
            'Pending', 'Approved', 'Rejected', 'Watchlist', 'Blocked', 'False Positive'
        )),
        CONSTRAINT CK_pending_change_type   CHECK (change_type IN (
            'ADD', 'ADD_UNKNOWN', 'UPDATE'
        ))
    )
    WITH (
        SYSTEM_VERSIONING = ON (HISTORY_TABLE = compass.pending_ai_registry_history),
        LEDGER = ON
    );

    PRINT 'Table [compass].[pending_ai_registry] created (updatable ledger).';
END
ELSE
    PRINT 'Table [compass].[pending_ai_registry] already exists. Skipping.';
GO


-- ------------------------------------------------------------
-- TABLE 3: approved_ai_registry
-- The official registry the detection engine reads from.
-- Only the approval stored procedure can insert here.
-- Updatable ledger with system versioning.
-- ------------------------------------------------------------
IF NOT EXISTS (
    SELECT 1 FROM sys.tables t
    JOIN sys.schemas s ON t.schema_id = s.schema_id
    WHERE s.name = 'compass' AND t.name = 'approved_ai_registry'
)
BEGIN
    CREATE TABLE [compass].[approved_ai_registry] (
        id                  INT             IDENTITY(1,1)   NOT NULL,
        domain_pattern      NVARCHAR(255)                   NOT NULL,
        normalized_domain   NVARCHAR(255)                   NOT NULL,
        tool_name           NVARCHAR(200)                   NOT NULL,
        category            NVARCHAR(100)                   NOT NULL,
        risk_level          NVARCHAR(50)                    NOT NULL,
        source_name         NVARCHAR(100)                   NOT NULL,
        approval_status     NVARCHAR(50)                    NOT NULL,
        approved_by         NVARCHAR(200)                   NOT NULL,
        approved_at         DATETIME2                       NOT NULL DEFAULT GETUTCDATE(),
        active              BIT                             NOT NULL DEFAULT 1,
        notes               NVARCHAR(2000)                  NULL,
        pending_id          INT                             NULL,
        registry_version    NVARCHAR(50)                    NULL,

        -- Required for updatable ledger: system versioning period columns
        ValidFrom   DATETIME2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL,
        ValidTo     DATETIME2 GENERATED ALWAYS AS ROW END   HIDDEN NOT NULL,
        PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo),

        CONSTRAINT PK_approved_ai_registry      PRIMARY KEY (id),
        CONSTRAINT UQ_approved_normalized_domain UNIQUE (normalized_domain),
        CONSTRAINT CK_approved_risk_level        CHECK (risk_level IN ('Low', 'Medium', 'High')),
        CONSTRAINT CK_approved_status            CHECK (approval_status IN (
            'Approved', 'Approved_Restricted', 'Monitor', 'Blocked'
        ))
    )
    WITH (
        SYSTEM_VERSIONING = ON (HISTORY_TABLE = compass.approved_ai_registry_history),
        LEDGER = ON
    );

    PRINT 'Table [compass].[approved_ai_registry] created (updatable ledger).';
END
ELSE
    PRINT 'Table [compass].[approved_ai_registry] already exists. Skipping.';
GO


-- ------------------------------------------------------------
-- Indexes for query performance
-- ------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pending_review_status')
    CREATE INDEX IX_pending_review_status
        ON [compass].[pending_ai_registry] (review_status)
        INCLUDE (domain_pattern, suggested_risk_level, requested_at);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_approved_active_domain')
    CREATE INDEX IX_approved_active_domain
        ON [compass].[approved_ai_registry] (active, normalized_domain)
        INCLUDE (tool_name, category, risk_level, approval_status);
GO

PRINT 'All tables and indexes created successfully.';
GO
