-- ============================================================
-- 003_create_procedures.sql
-- Stored procedures for the registry approval workflow.
-- Reviewers must use these procedures - they cannot INSERT
-- directly into approved_ai_registry.
-- ============================================================


-- ------------------------------------------------------------
-- PROCEDURE 1: usp_ApproveRegistryEntry
-- Moves a pending record into the approved registry.
-- Requires: pending record ID, final tool/category/risk, approver name.
-- ------------------------------------------------------------
CREATE OR ALTER PROCEDURE [compass].[usp_ApproveRegistryEntry]
    @pending_id         INT,
    @tool_name          NVARCHAR(200),
    @category           NVARCHAR(100),
    @risk_level         NVARCHAR(50),       -- Low | Medium | High
    @approval_status    NVARCHAR(50),       -- Approved | Approved_Restricted | Monitor | Blocked
    @approver_name      NVARCHAR(200),
    @notes              NVARCHAR(2000) = NULL,
    @registry_version   NVARCHAR(50)   = NULL
AS
BEGIN
    SET NOCOUNT ON;

    -- Validate risk level
    IF @risk_level NOT IN ('Low', 'Medium', 'High')
    BEGIN
        RAISERROR('Invalid risk_level. Must be Low, Medium, or High.', 16, 1);
        RETURN;
    END

    -- Validate approval status
    IF @approval_status NOT IN ('Approved', 'Approved_Restricted', 'Monitor', 'Blocked')
    BEGIN
        RAISERROR('Invalid approval_status. Must be Approved, Approved_Restricted, Monitor, or Blocked.', 16, 1);
        RETURN;
    END

    -- Confirm pending record exists and is still Pending
    IF NOT EXISTS (
        SELECT 1 FROM [compass].[pending_ai_registry]
        WHERE id = @pending_id AND review_status = 'Pending'
    )
    BEGIN
        RAISERROR('Pending record not found or already reviewed. ID: %d', 16, 1, @pending_id);
        RETURN;
    END

    DECLARE @domain_pattern     NVARCHAR(255);
    DECLARE @normalized_domain  NVARCHAR(255);
    DECLARE @source_name        NVARCHAR(100);

    SELECT
        @domain_pattern     = domain_pattern,
        @normalized_domain  = normalized_domain,
        @source_name        = source_name
    FROM [compass].[pending_ai_registry]
    WHERE id = @pending_id;

    BEGIN TRANSACTION;
    BEGIN TRY

        -- Check if this domain already exists in approved registry (update if so)
        IF EXISTS (
            SELECT 1 FROM [compass].[approved_ai_registry]
            WHERE normalized_domain = @normalized_domain
        )
        BEGIN
            UPDATE [compass].[approved_ai_registry]
            SET
                domain_pattern   = @domain_pattern,
                tool_name        = @tool_name,
                category         = @category,
                risk_level       = @risk_level,
                approval_status  = @approval_status,
                approved_by      = @approver_name,
                approved_at      = GETUTCDATE(),
                active           = 1,
                notes            = @notes,
                pending_id       = @pending_id,
                registry_version = @registry_version
            WHERE normalized_domain = @normalized_domain;
        END
        ELSE
        BEGIN
            -- Insert into approved registry
            INSERT INTO [compass].[approved_ai_registry] (
                domain_pattern, normalized_domain, tool_name, category,
                risk_level, source_name, approval_status, approved_by,
                approved_at, active, notes, pending_id, registry_version
            )
            VALUES (
                @domain_pattern, @normalized_domain, @tool_name, @category,
                @risk_level, @source_name, @approval_status, @approver_name,
                GETUTCDATE(), 1, @notes, @pending_id, @registry_version
            );
        END

        -- Mark pending record as Approved
        UPDATE [compass].[pending_ai_registry]
        SET
            review_status  = 'Approved',
            reviewer_name  = @approver_name,
            reviewer_notes = @notes,
            reviewed_at    = GETUTCDATE()
        WHERE id = @pending_id;

        COMMIT TRANSACTION;
        PRINT 'Record approved and added to registry. Pending ID: ' + CAST(@pending_id AS NVARCHAR);

    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION;
        DECLARE @err NVARCHAR(4000) = ERROR_MESSAGE();
        RAISERROR('Approval failed: %s', 16, 1, @err);
    END CATCH
END
GO


-- ------------------------------------------------------------
-- PROCEDURE 2: usp_RejectRegistryEntry
-- Marks a pending record as rejected. Does NOT delete it.
-- Rejected records remain as evidence the team reviewed it.
-- ------------------------------------------------------------
CREATE OR ALTER PROCEDURE [compass].[usp_RejectRegistryEntry]
    @pending_id     INT,
    @reviewer_name  NVARCHAR(200),
    @reviewer_notes NVARCHAR(2000)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (
        SELECT 1 FROM [compass].[pending_ai_registry]
        WHERE id = @pending_id AND review_status = 'Pending'
    )
    BEGIN
        RAISERROR('Pending record not found or already reviewed. ID: %d', 16, 1, @pending_id);
        RETURN;
    END

    UPDATE [compass].[pending_ai_registry]
    SET
        review_status  = 'Rejected',
        reviewer_name  = @reviewer_name,
        reviewer_notes = @reviewer_notes,
        reviewed_at    = GETUTCDATE()
    WHERE id = @pending_id;

    PRINT 'Record rejected. Pending ID: ' + CAST(@pending_id AS NVARCHAR);
END
GO


-- ------------------------------------------------------------
-- PROCEDURE 3: usp_WatchlistRegistryEntry
-- Marks a pending record as Watchlist (needs more info).
-- ------------------------------------------------------------
CREATE OR ALTER PROCEDURE [compass].[usp_WatchlistRegistryEntry]
    @pending_id     INT,
    @reviewer_name  NVARCHAR(200),
    @reviewer_notes NVARCHAR(2000) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (
        SELECT 1 FROM [compass].[pending_ai_registry]
        WHERE id = @pending_id AND review_status = 'Pending'
    )
    BEGIN
        RAISERROR('Pending record not found or already reviewed. ID: %d', 16, 1, @pending_id);
        RETURN;
    END

    UPDATE [compass].[pending_ai_registry]
    SET
        review_status  = 'Watchlist',
        reviewer_name  = @reviewer_name,
        reviewer_notes = @reviewer_notes,
        reviewed_at    = GETUTCDATE()
    WHERE id = @pending_id;

    PRINT 'Record placed on watchlist. Pending ID: ' + CAST(@pending_id AS NVARCHAR);
END
GO


-- ------------------------------------------------------------
-- PROCEDURE 4: usp_GetPendingItems
-- Returns all pending items for the review queue.
-- Called by the reviewer UI or Azure Data Studio.
-- ------------------------------------------------------------
CREATE OR ALTER PROCEDURE [compass].[usp_GetPendingItems]
    @status NVARCHAR(50) = 'Pending'    -- Default: only unreviewed items
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        id,
        domain_pattern,
        normalized_domain,
        source_name,
        change_type,
        suggested_tool_name,
        suggested_category,
        suggested_risk_level,
        review_status,
        requested_at,
        first_seen,
        last_seen,
        user_count,
        request_count,
        data_uploads_observed,
        log_source,
        reviewer_notes
    FROM [compass].[pending_ai_registry]
    WHERE review_status = @status
    ORDER BY
        CASE suggested_risk_level
            WHEN 'High'        THEN 1
            WHEN 'Medium-High' THEN 2
            WHEN 'Medium'      THEN 3
            WHEN 'Low'         THEN 4
            ELSE 5
        END,
        requested_at ASC;
END
GO


-- ------------------------------------------------------------
-- PROCEDURE 5: usp_GetApprovedRegistry
-- Returns the active approved registry for the detection engine.
-- The detection engine user (compass_reader) can only call this.
-- ------------------------------------------------------------
CREATE OR ALTER PROCEDURE [compass].[usp_GetApprovedRegistry]
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        id,
        domain_pattern,
        normalized_domain,
        tool_name,
        category,
        risk_level,
        approval_status,
        source_name,
        approved_at,
        registry_version
    FROM [compass].[approved_ai_registry]
    WHERE active = 1
    ORDER BY tool_name ASC;
END
GO


-- ------------------------------------------------------------
-- PROCEDURE 6: usp_DeactivateRegistryEntry
-- Disables an approved entry without deleting it.
-- Ledger history is preserved.
-- ------------------------------------------------------------
CREATE OR ALTER PROCEDURE [compass].[usp_DeactivateRegistryEntry]
    @registry_id    INT,
    @reviewer_name  NVARCHAR(200),
    @reason         NVARCHAR(2000) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (
        SELECT 1 FROM [compass].[approved_ai_registry]
        WHERE id = @registry_id AND active = 1
    )
    BEGIN
        RAISERROR('Active registry entry not found. ID: %d', 16, 1, @registry_id);
        RETURN;
    END

    UPDATE [compass].[approved_ai_registry]
    SET
        active      = 0,
        notes       = ISNULL(@reason, notes),
        approved_by = @reviewer_name,
        approved_at = GETUTCDATE()
    WHERE id = @registry_id;

    PRINT 'Registry entry deactivated. ID: ' + CAST(@registry_id AS NVARCHAR);
END
GO

PRINT 'All stored procedures created successfully.';
GO
