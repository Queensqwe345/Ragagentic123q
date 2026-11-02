-- RUN SECOND in the SAME intended UAT database after 01_Backup_Four_Procedures.sql.
-- Covers the four outstanding API signatures, the missing source-request table,
-- and the permission catalogue Description dependency if it is absent.
-- No USE statement, application data changes, role grants or feature activation.
-- Table must be absent, as reported by UAT. Existing objects are not replaced blindly.
-- All schema and procedure updates below commit together or roll back together.
SET NOCOUNT ON;
SET XACT_ABORT ON;
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_PADDING ON;
SET ANSI_WARNINGS ON;
SET ARITHABORT ON;
SET CONCAT_NULL_YIELDS_NULL ON;
SET NUMERIC_ROUNDABORT OFF;
IF @@TRANCOUNT<>0 THROW 51090,'Run outside an existing transaction.',1;
DECLARE @Expected TABLE(OriginalName sysname,BackupName sysname);

INSERT @Expected VALUES
 (N'commit_accessIdentity',N'commit_accessIdentity2nov2026backup'),
 (N'commit_accessPermissionCatalog',N'commit_accessPermissionCatalog2nov2026backup'),
 (N'sel_accessGroupMappings',N'sel_accessGroupMappings2nov2026backup'),
 (N'sel_accessProcessList',N'sel_accessProcessList2nov2026backup');

BEGIN TRY
 BEGIN TRANSACTION;
 IF EXISTS (
  SELECT 1 FROM @Expected e
  LEFT JOIN sys.sql_modules m ON m.object_id=OBJECT_ID(N'dbo.'+e.OriginalName,N'P')
  LEFT JOIN sys.extended_properties ep ON ep.class=1 AND ep.minor_id=0
   AND ep.major_id=OBJECT_ID(N'dbo.'+e.BackupName,N'P') AND ep.name=N'DI_BackupOriginalSHA256'
  WHERE m.definition IS NULL OR ep.value IS NULL
   OR CONVERT(varchar(64),ep.value)<>CONVERT(varchar(64),HASHBYTES('SHA2_256',CONVERT(varbinary(max),m.definition)),2)
 ) THROW 51090,'Missing backup or original changed since backup. No updates applied.',1;
 IF OBJECT_ID(N'dbo.di_sourceSetupRequest') IS NOT NULL
  THROW 51090,'di_sourceSetupRequest already exists. Review its schema before using this missing-table package.',1;

 IF EXISTS (SELECT 1 FROM (VALUES
 (N'dbo.di_accessAudit'),
 (N'dbo.di_application'),
 (N'dbo.di_AppUsers'),
 (N'dbo.di_authChallenge'),
 (N'dbo.di_databaseConfiguration'),
 (N'dbo.di_flpConfiguration'),
 (N'dbo.di_flpConfigurationSecurityGroupMapping'),
 (N'dbo.di_gdrive_tenant'),
 (N'dbo.di_group'),
 (N'dbo.di_groupMembership'),
 (N'dbo.di_groupRoleMapping'),
 (N'dbo.di_groupScopeMapping'),
 (N'dbo.di_info_clientnames'),
 (N'dbo.di_info_databricksInstance'),
 (N'dbo.di_info_permission'),
 (N'dbo.di_info_region'),
 (N'dbo.di_info_securityGroup'),
 (N'dbo.di_info_storageAccountDetails'),
 (N'dbo.di_info_sub_region'),
 (N'dbo.di_role'),
 (N'dbo.di_rolePermission'),
 (N'dbo.di_userAccount'),
 (N'dbo.di_userIdentity'),
 (N'dbo.di_userLegacyLink'),
 (N'dbo.di_userRoleMapping'),
 (N'dbo.di_userSession')
 ) required(ObjectName) WHERE OBJECT_ID(required.ObjectName) IS NULL)
  THROW 51090,'A required Access or business catalogue object is missing. No updates applied.',1;

 IF COL_LENGTH(N'dbo.di_info_permission',N'Description') IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM sys.columns WHERE object_id=OBJECT_ID(N'dbo.di_info_permission')
  AND name=N'Description' AND system_type_id=231 AND max_length=600 AND is_nullable=1 AND is_computed=0)
  THROW 51090,'Existing permission Description column differs from expected nvarchar(300) NULL. Review before applying.',1;
 IF COL_LENGTH(N'dbo.di_info_permission',N'Description') IS NULL
  EXEC sys.sp_executesql N'ALTER TABLE dbo.di_info_permission ADD Description nvarchar(300) NULL;';

 -- Source-request storage, defaults, primary key, check constraints, foreign keys and indexes.
 EXEC sys.sp_executesql N'CREATE TABLE dbo.di_sourceSetupRequest (
    [RequestId] bigint IDENTITY(1,1) NOT NULL,
    [GroupId] uniqueidentifier NOT NULL,
    [RequestedByUserId] uniqueidentifier NOT NULL,
    [SourceKind] varchar(16) NOT NULL,
    [DisplayName] nvarchar(120) NOT NULL,
    [LocationUrl] nvarchar(512) NOT NULL,
    [Details] nvarchar(1000) NULL,
    [RegionId] int NOT NULL,
    [SubRegionId] int NOT NULL,
    [ClientId] int NOT NULL,
    [RequestStatus] tinyint NOT NULL CONSTRAINT DF_access_di_sourceSetupRequest_RequestStatus DEFAULT (1),
    [ResourceId] nvarchar(64) NULL,
    [ResolutionNote] nvarchar(1000) NULL,
    [ResolvedByUserId] uniqueidentifier NULL,
    [CreatedAtUTC] datetime2(3) NOT NULL CONSTRAINT DF_access_di_sourceSetupRequest_CreatedAtUTC DEFAULT (SYSUTCDATETIME()),
    [UpdatedAtUTC] datetime2(3) NULL,
    [RowVersion] rowversion,
    CONSTRAINT PK_access_di_sourceSetupRequest PRIMARY KEY (RequestId),
    CONSTRAINT CK_accessSourceKind CHECK (SourceKind IN (''SHAREPOINT'',''GDRIVE'')),
    CONSTRAINT CK_accessSourceRequestStatus CHECK (RequestStatus BETWEEN 1 AND 5)
);

ALTER TABLE dbo.di_sourceSetupRequest ADD CONSTRAINT FK_access_61 FOREIGN KEY (GroupId) REFERENCES dbo.di_group (GroupId) ON DELETE NO ACTION ON UPDATE NO ACTION;

ALTER TABLE dbo.di_sourceSetupRequest ADD CONSTRAINT FK_access_62 FOREIGN KEY (RequestedByUserId) REFERENCES dbo.di_userAccount (UserId) ON DELETE NO ACTION ON UPDATE NO ACTION;

ALTER TABLE dbo.di_sourceSetupRequest ADD CONSTRAINT FK_access_63 FOREIGN KEY (ResolvedByUserId) REFERENCES dbo.di_userAccount (UserId) ON DELETE NO ACTION ON UPDATE NO ACTION;

CREATE INDEX IX_accessSourceRequestGroup ON dbo.di_sourceSetupRequest (GroupId,RequestId);

CREATE INDEX IX_accessSourceRequestUser ON dbo.di_sourceSetupRequest (RequestedByUserId,GroupId,RequestId);';

 -- dbo.commit_accessIdentity
 EXEC sys.sp_executesql N'CREATE OR ALTER PROCEDURE dbo.commit_accessIdentity
    @OperationId uniqueidentifier,
    @RequestHash binary(32),
    @CorrelationId uniqueidentifier,
    @ExpectedRowVersion binary(8)=NULL,
    @Command varchar(16),
    @UserId uniqueidentifier=NULL,
    @ProviderTypeId smallint,
    @ProviderNamespace varchar(128),
    @SubjectId varchar(255),
    @VerifiedEmail nvarchar(320)=NULL,
    @EmailVerified bit,
    @DisplayName nvarchar(200),
    @LinkChallengeId uniqueidentifier=NULL,
    @CompanyDirectoryEligible bit=0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @Now datetime2(3)=SYSUTCDATETIME();
    IF ISNULL(IS_MEMBER(N''access_auth_executor''),0)<>1 AND ISNULL(IS_MEMBER(N''db_owner''),0)<>1 THROW 51003,''ACCESS_SERVICE_ROLE_REQUIRED'',1;

    IF @OperationId IS NULL OR @RequestHash IS NULL OR @CorrelationId IS NULL THROW 51002,''ACCESS_COMMAND_METADATA_REQUIRED'',1;
    BEGIN TRY
      BEGIN TRANSACTION;

      DECLARE @LockResult int;
      DECLARE @LockName nvarchar(255)=N''DIAccessCommand:''+CONVERT(nvarchar(36),@OperationId);
      EXEC @LockResult=sys.sp_getapplock @Resource=@LockName,@LockMode=''Exclusive'',@LockOwner=''Transaction'',@LockTimeout=5000;
      IF @LockResult<0 THROW 51009,''ACCESS_COMMAND_BUSY'',1;
      IF EXISTS (SELECT 1 FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0)
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0 AND RequestHash=@RequestHash AND EventCode=''commit_accessIdentity'' AND ActorServiceCode=''AUTH'') THROW 51004,''ACCESS_IDEMPOTENCY_CONFLICT'',1;
        SELECT ''AlreadyApplied'' Disposition,TargetKey FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0;
        COMMIT TRANSACTION; RETURN;
      END;

      IF @Command NOT IN (''RESOLVE'',''LINK'',''REGISTER'') THROW 51020,''ACCESS_PROVISIONING_REQUIRES_INVITATION'',1;
      IF @ProviderTypeId NOT IN (1,2) OR LEN(@ProviderNamespace)=0 OR LEN(@SubjectId)=0 THROW 51002,''ACCESS_PROVIDER_IDENTITY_INVALID'',1;

      IF @ProviderTypeId=2 AND (@ProviderNamespace NOT IN (''https://accounts.google.com'',''accounts.google.com'') OR @EmailVerified<>1 OR NULLIF(@VerifiedEmail,N'''') IS NULL)
        THROW 51002,''ACCESS_PROVIDER_IDENTITY_INVALID'',1;
      IF @ProviderTypeId=1 AND (TRY_CONVERT(uniqueidentifier,@ProviderNamespace) IS NULL OR TRY_CONVERT(uniqueidentifier,@SubjectId) IS NULL)
        THROW 51002,''ACCESS_PROVIDER_IDENTITY_INVALID'',1;
      DECLARE @IdentityId bigint,@ResolvedUserId uniqueidentifier;
      DECLARE @IdentityLock nvarchar(255)=N''DIAccessIdentity:''+CONVERT(varchar(64),HASHBYTES(''SHA2_256'',CONCAT(@ProviderTypeId,'':'',CASE WHEN @ProviderTypeId=2 THEN ''https://accounts.google.com'' ELSE @ProviderNamespace END,'':'',@SubjectId)),2);
      EXEC @LockResult=sys.sp_getapplock @Resource=@IdentityLock,@LockMode=''Exclusive'',@LockOwner=''Transaction'',@LockTimeout=5000;
      IF @LockResult<0 THROW 51009,''ACCESS_COMMAND_BUSY'',1;
      -- Google accepts two issuer spellings; never create a second account for the same sub.
      IF @ProviderTypeId=2
      BEGIN
        IF (SELECT COUNT(*) FROM dbo.di_userIdentity WHERE ProviderTypeId=2 AND SubjectId=@SubjectId COLLATE Latin1_General_100_BIN2 AND ProviderNamespace IN (''https://accounts.google.com'',''accounts.google.com''))>1
          THROW 51022,''ACCESS_IDENTITY_ALREADY_LINKED'',1;
        SET @ProviderNamespace=COALESCE((SELECT ProviderNamespace FROM dbo.di_userIdentity WHERE ProviderTypeId=2 AND SubjectId=@SubjectId COLLATE Latin1_General_100_BIN2 AND ProviderNamespace IN (''https://accounts.google.com'',''accounts.google.com'')),''https://accounts.google.com'');
      END;

      SELECT @IdentityId=IdentityId,@ResolvedUserId=UserId FROM dbo.di_userIdentity WITH(UPDLOCK,HOLDLOCK) WHERE ProviderTypeId=@ProviderTypeId AND ProviderNamespace=@ProviderNamespace COLLATE Latin1_General_100_BIN2 AND SubjectId=@SubjectId COLLATE Latin1_General_100_BIN2;

      IF @Command=''REGISTER''
      BEGIN
        IF @UserId IS NOT NULL OR @LinkChallengeId IS NOT NULL THROW 51002,''ACCESS_PROVIDER_IDENTITY_INVALID'',1;
        IF @IdentityId IS NULL
        BEGIN
          SET @ResolvedUserId=NEWID();
          INSERT dbo.di_userAccount(UserId,DisplayName,ContactEmail,IsExternal,PreferredProviderTypeId,AccountStatus)
            VALUES(@ResolvedUserId,@DisplayName,CASE WHEN @EmailVerified=1 THEN @VerifiedEmail ELSE NULL END,CASE WHEN @CompanyDirectoryEligible=1 THEN 0 ELSE 1 END,@ProviderTypeId,2);
          INSERT dbo.di_userIdentity(UserId,ProviderTypeId,ProviderNamespace,SubjectId,Email,EmailVerified,IdentityStatus,VerifiedAtUTC)
            VALUES(@ResolvedUserId,@ProviderTypeId,@ProviderNamespace,@SubjectId,@VerifiedEmail,@EmailVerified,2,@Now);
          SET @IdentityId=SCOPE_IDENTITY();
        END;
        -- No email-based merge, membership, role, bootstrap or legacy identity is created.
      END;
      IF @Command=''LINK''
      BEGIN
        IF @UserId IS NULL OR NOT EXISTS(SELECT 1 FROM dbo.di_authChallenge c JOIN dbo.di_userAccount u ON u.UserId=c.UserId WHERE c.ChallengeId=@LinkChallengeId AND c.UserId=@UserId AND c.PurposeCode IN (1,6) AND c.ChallengeStatus=1 AND c.ExpiresAtUTC>@Now AND c.RequiredUserSecurityVersion=u.SecurityVersion AND u.AccountStatus IN (1,2)) THROW 51021,''ACCESS_LINK_PROOF_REQUIRED'',1;
        IF @IdentityId IS NOT NULL AND @ResolvedUserId<>@UserId THROW 51022,''ACCESS_IDENTITY_ALREADY_LINKED'',1;
        IF @IdentityId IS NULL
        BEGIN
          INSERT dbo.di_userIdentity(UserId,ProviderTypeId,ProviderNamespace,SubjectId,Email,EmailVerified,IdentityStatus,VerifiedAtUTC) VALUES(@UserId,@ProviderTypeId,@ProviderNamespace,@SubjectId,@VerifiedEmail,@EmailVerified,2,@Now);
          SET @IdentityId=SCOPE_IDENTITY(); SET @ResolvedUserId=@UserId;
        END;
        UPDATE dbo.di_authChallenge SET ChallengeStatus=2,ConsumedAtUTC=@Now WHERE ChallengeId=@LinkChallengeId AND ChallengeStatus=1;
        IF @@ROWCOUNT<>1 THROW 51021,''ACCESS_LINK_PROOF_USED'',1;
        UPDATE dbo.di_userAccount SET AccountStatus=2,ModificationDateTime=@Now WHERE UserId=@UserId AND AccountStatus=1;
      END;
      IF @IdentityId IS NULL THROW 51023,''ACCESS_IDENTITY_NOT_REGISTERED'',1;
      IF NOT EXISTS(SELECT 1 FROM dbo.di_userIdentity i JOIN dbo.di_userAccount u ON u.UserId=i.UserId WHERE i.IdentityId=@IdentityId AND i.IdentityStatus=2 AND u.AccountStatus=2) THROW 51024,''ACCESS_ACCOUNT_DISABLED'',1;
      UPDATE dbo.di_userIdentity SET VerifiedAtUTC=@Now,Email=@VerifiedEmail,EmailVerified=@EmailVerified,ModificationDateTime=@Now WHERE IdentityId=@IdentityId;
      SELECT u.UserId,i.IdentityId,u.AccountStatus,i.IdentityStatus,u.SecurityVersion,u.IsExternal,u.DisplayName,i.Email,i.EmailVerified,i.ProviderTypeId,i.ProviderNamespace,i.SubjectId,u.RowVersion FROM dbo.di_userIdentity i JOIN dbo.di_userAccount u ON u.UserId=i.UserId WHERE i.IdentityId=@IdentityId;

      INSERT dbo.di_accessAudit(OperationId,RequestHash,ActorUserId,ActorServiceCode,GroupId,EventCode,TargetType,TargetKey,Outcome,ChangeSummary,CorrelationId)
      VALUES(@OperationId,@RequestHash,NULL,''AUTH'',NULL,''commit_accessIdentity'',''ACCESS'',COALESCE(CONVERT(nvarchar(200),@ResolvedUserId),N''''),1,N''Command=''+@Command,@CorrelationId);
      COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
      IF XACT_STATE()<>0 ROLLBACK TRANSACTION;
      THROW;
    END CATCH;
END;';

 -- dbo.commit_accessPermissionCatalog
 EXEC sys.sp_executesql N'CREATE OR ALTER PROCEDURE dbo.commit_accessPermissionCatalog
    @ActorUserId uniqueidentifier,
    @ActorSessionId uniqueidentifier,
    @SessionHash binary(32),
    @OperationId uniqueidentifier,
    @RequestHash binary(32),
    @CorrelationId uniqueidentifier,
    @ExpectedRowVersion binary(8)=NULL,
    @PermissionId int=NULL,
    @PermissionCode varchar(100),
    @ParentPermissionId int=NULL,
    @NodeKind char(1),
    @DisplayName nvarchar(120),
    @RouteKey varchar(100)=NULL,
    @IconKey varchar(100)=NULL,
    @SortOrder int,
    @AllowedScopeMask int,
    @IsActive bit,
    @Command varchar(10)=''UPDATE'',
    @Description nvarchar(300)=NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @Now datetime2(3)=SYSUTCDATETIME();
    IF @OperationId IS NULL OR @RequestHash IS NULL OR @CorrelationId IS NULL THROW 51002,''ACCESS_COMMAND_METADATA_REQUIRED'',1;
    BEGIN TRY
      BEGIN TRANSACTION;
    IF NOT EXISTS (SELECT 1 FROM dbo.di_userSession s WITH(HOLDLOCK) JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=s.UserId JOIN dbo.di_userIdentity i WITH(HOLDLOCK) ON i.IdentityId=s.IdentityId AND i.UserId=s.UserId WHERE s.SessionId=@ActorSessionId AND s.SessionHash=@SessionHash AND s.UserId=@ActorUserId AND s.RevokedAtUTC IS NULL AND s.AbsoluteExpiresAtUTC>@Now AND s.IdleExpiresAtUTC>@Now AND s.UserSecurityVersion=u.SecurityVersion AND u.AccountStatus=2 AND i.IdentityStatus=2) THROW 51001,''ACCESS_SESSION_INVALID'',1;
    DECLARE @ScopeGroupId uniqueidentifier=NULL;
    DECLARE @AccessPermissions TABLE(PermissionCode varchar(100) PRIMARY KEY,DataScopeCode tinyint NOT NULL);
    ;WITH EligibleRoles AS (
      SELECT ur.RoleId,r.Priority FROM dbo.di_userRoleMapping ur WITH(HOLDLOCK) JOIN dbo.di_role r WITH(HOLDLOCK) ON r.RoleId=ur.RoleId AND r.IsActive=1
      WHERE ur.UserId=@ActorUserId AND ur.IsActive=1 AND ur.BeginsAtUTC<=@Now AND (ur.EndsAtUTC IS NULL OR ur.EndsAtUTC>@Now)
      AND ((ur.GrantScope=''A'' AND ur.RoleId IN (4,5)) OR (ur.GrantScope=''G'' AND ur.GroupId=@ScopeGroupId AND EXISTS (
        SELECT 1 FROM dbo.di_groupMembership m WITH(HOLDLOCK) JOIN dbo.di_group g WITH(HOLDLOCK) ON g.GroupId=m.GroupId JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=m.UserId LEFT JOIN dbo.di_userIdentity pi WITH(HOLDLOCK) ON pi.IdentityId=m.ProofIdentityId
        JOIN dbo.di_groupRoleMapping gr WITH(HOLDLOCK) ON gr.GroupId=m.GroupId AND gr.RoleId=ur.RoleId AND gr.IsActive=1
        WHERE m.MembershipId=ur.MembershipId AND m.UserId=ur.UserId AND ur.GrantMembershipEpoch=m.MembershipEpoch AND m.LocalState=1 AND m.ApprovalStatus IN (0,2,4) AND g.GroupStatus=2 AND (u.IsExternal=0 OR g.ProviderTypeId=3) AND (g.ProviderTypeId=3 OR (m.ProofStatus=1 AND m.ProofExpiresAtUTC>@Now AND m.ProofObservedAtUTC>=DATEADD(minute,-15,@Now) AND pi.IdentityStatus=2 AND pi.UserId=m.UserId AND pi.ProviderTypeId=g.ProviderTypeId AND ((g.ProviderTypeId=1 AND pi.ProviderNamespace=g.DirectoryKey) OR (g.ProviderTypeId=2 AND pi.ProviderNamespace IN (''https://accounts.google.com'',''accounts.google.com''))))))))
      AND (@ScopeGroupId IS NULL OR EXISTS (SELECT 1 FROM dbo.di_group g JOIN dbo.di_userAccount u ON u.UserId=@ActorUserId WHERE g.GroupId=@ScopeGroupId AND g.GroupStatus<>4 AND (u.IsExternal=0 OR g.ProviderTypeId=3)))
    ), Chosen AS (SELECT RoleId FROM EligibleRoles WHERE Priority=(SELECT MAX(Priority) FROM EligibleRoles))
    INSERT @AccessPermissions SELECT p.PermissionCode,MAX(rp.DataScopeCode) FROM Chosen c JOIN dbo.di_rolePermission rp WITH(HOLDLOCK) ON rp.RoleId=c.RoleId AND rp.IsActive=1 JOIN dbo.di_info_permission p WITH(HOLDLOCK) ON p.PermissionId=rp.PermissionId AND p.IsActive=1 GROUP BY p.PermissionCode;
    IF NOT EXISTS (SELECT 1 FROM @AccessPermissions WHERE PermissionCode=''PERMISSION.MANAGE'') THROW 51003,''ACCESS_PERMISSION_DENIED'',1;

      DECLARE @LockResult int;
      DECLARE @LockName nvarchar(255)=N''DIAccessCommand:''+CONVERT(nvarchar(36),@OperationId);
      EXEC @LockResult=sys.sp_getapplock @Resource=@LockName,@LockMode=''Exclusive'',@LockOwner=''Transaction'',@LockTimeout=5000;
      IF @LockResult<0 THROW 51009,''ACCESS_COMMAND_BUSY'',1;
      IF EXISTS (SELECT 1 FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0)
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0 AND RequestHash=@RequestHash AND EventCode=''commit_accessPermissionCatalog'' AND ActorUserId=@ActorUserId) THROW 51004,''ACCESS_IDEMPOTENCY_CONFLICT'',1;
        SELECT ''AlreadyApplied'' Disposition,TargetKey FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0;
        COMMIT TRANSACTION; RETURN;
      END;


      IF @Command NOT IN (''CREATE'',''UPDATE'',''REMOVE'',''ASSET'') THROW 51002,''ACCESS_MENU_COMMAND_INVALID'',1;
      IF @Command=''ASSET''
      BEGIN
        IF @IconKey IS NULL OR LEN(@IconKey)<>74 OR LEFT(@IconKey,6)<>''asset-'' OR RIGHT(@IconKey,4)<>''.png'' OR SUBSTRING(@IconKey,7,64) COLLATE Latin1_General_100_BIN2 LIKE ''%[^0-9a-f]%''
          THROW 51002,''ACCESS_ICON_NOT_ALLOWLISTED'',1;
        SELECT @IconKey AS IconKey;
      END
      ELSE
      BEGIN
        IF NULLIF(LTRIM(RTRIM(@DisplayName)),N'''') IS NULL OR @SortOrder NOT BETWEEN 0 AND 100000 THROW 51002,''ACCESS_MENU_PRESENTATION_INVALID'',1;
        IF @IconKey IS NOT NULL AND @IconKey NOT IN (''dashboard'',''process'',''monitor'',''administration'',''groups'',''users'',''permissions'',''source'',''reports'',''settings'')
          AND NOT EXISTS(SELECT 1 FROM dbo.di_accessAudit WHERE EventCode=''commit_accessPermissionCatalog'' AND TargetKey=@IconKey AND ChangeSummary=N''Command=ASSET'' AND Outcome=1)
          THROW 51002,''ACCESS_ICON_NOT_ALLOWLISTED'',1;
        IF @Command=''CREATE''
        BEGIN
          IF @PermissionId IS NOT NULL OR @NodeKind NOT IN (''N'',''M'') OR @AllowedScopeMask<>1 OR @IsActive<>1
            OR @PermissionCode NOT LIKE ''MENU.CUSTOM.%'' OR LEN(@PermissionCode)>100 THROW 51002,''ACCESS_CUSTOM_MENU_INVALID'',1;
          IF (@NodeKind=''N'' AND (@ParentPermissionId IS NOT NULL OR @RouteKey IS NOT NULL)) OR
            (@NodeKind=''M'' AND (@RouteKey IS NULL OR @RouteKey NOT IN (''dashboard'',''process-list'',''real-time-status'',''processed-files'',''access-users'',''access-groups'',''access-approvals'',''access-role-assignments'',''access-role-permissions'',''source-connect''))) THROW 51002,''ACCESS_MENU_ROUTE_NOT_REVIEWED'',1;
          IF @ParentPermissionId IS NOT NULL AND NOT EXISTS(SELECT 1 FROM dbo.di_info_permission WHERE PermissionId=@ParentPermissionId AND NodeKind=''N'' AND IsActive=1) THROW 51002,''ACCESS_MENU_PARENT_INVALID'',1;
          INSERT dbo.di_info_permission(PermissionCode,ParentPermissionId,NodeKind,DisplayName,RouteKey,IconKey,Description,SortOrder,AllowedScopeMask,IsActive,CreatedByUserId)
          VALUES(@PermissionCode,@ParentPermissionId,@NodeKind,LTRIM(RTRIM(@DisplayName)),@RouteKey,@IconKey,@Description,@SortOrder,1,1,@ActorUserId);
          SET @PermissionId=SCOPE_IDENTITY();
          -- Presentation creation does not grant this menu or any executable action to any role.
        END
        ELSE
        BEGIN
          IF @PermissionId IS NULL OR @ExpectedRowVersion IS NULL THROW 51002,''ACCESS_EXISTING_ALLOWLIST_KEY_REQUIRED'',1;
          IF NOT EXISTS(SELECT 1 FROM dbo.di_info_permission WITH(UPDLOCK,HOLDLOCK) WHERE PermissionId=@PermissionId AND PermissionCode=@PermissionCode AND RowVersion=@ExpectedRowVersion AND NodeKind=@NodeKind AND ISNULL(ParentPermissionId,0)=ISNULL(@ParentPermissionId,0) AND ISNULL(RouteKey,'''')=ISNULL(@RouteKey,'''') AND AllowedScopeMask=@AllowedScopeMask)
            THROW 51005,''ACCESS_CONCURRENCY_CONFLICT'',1;
          IF @NodeKind=''A'' OR (@Command=''REMOVE'' AND @NodeKind=''N'' AND EXISTS(SELECT 1 FROM dbo.di_info_permission WHERE ParentPermissionId=@PermissionId AND IsActive=1)) THROW 51003,''ACCESS_EXECUTABLE_CATALOG_IMMUTABLE'',1;
          UPDATE dbo.di_info_permission SET DisplayName=LTRIM(RTRIM(@DisplayName)),IconKey=@IconKey,Description=COALESCE(@Description,Description),SortOrder=@SortOrder,IsActive=CASE WHEN @Command=''REMOVE'' THEN 0 ELSE @IsActive END,ModificationDateTime=@Now,ModifiedByUserId=@ActorUserId WHERE PermissionId=@PermissionId;
        END;
        UPDATE dbo.di_role SET PolicyVersion=PolicyVersion+1,ModificationDateTime=@Now WHERE RoleId IN (SELECT RoleId FROM dbo.di_rolePermission WHERE PermissionId=@PermissionId);
        SELECT PermissionId,PermissionCode,DisplayName,Description,IsActive,RowVersion FROM dbo.di_info_permission WHERE PermissionId=@PermissionId;
      END;

      INSERT dbo.di_accessAudit(OperationId,RequestHash,ActorUserId,ActorServiceCode,GroupId,EventCode,TargetType,TargetKey,Outcome,ChangeSummary,CorrelationId)
      VALUES(@OperationId,@RequestHash,@ActorUserId,NULL,NULL,''commit_accessPermissionCatalog'',''ACCESS'',CASE WHEN @Command=''ASSET'' THEN @IconKey ELSE CONVERT(nvarchar(200),@PermissionId) END,1,N''Command=''+@Command,@CorrelationId);
      COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
      IF XACT_STATE()<>0 ROLLBACK TRANSACTION;
      THROW;
    END CATCH;
END;';

 -- dbo.sel_accessGroupMappings
 EXEC sys.sp_executesql N'CREATE OR ALTER PROCEDURE dbo.sel_accessGroupMappings
    @ActorUserId uniqueidentifier,
    @ActorSessionId uniqueidentifier,
    @SessionHash binary(32),
    @GroupId uniqueidentifier,
    @MappingKind char(1),
    @AfterMappingId bigint=NULL,
    @Take int=50,
    @CatalogKind varchar(16)=NULL,
    @Search nvarchar(100)=NULL,
    @ParentId int=NULL,
    @AfterValue nvarchar(64)=NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @Now datetime2(3)=SYSUTCDATETIME();
    IF NOT EXISTS (SELECT 1 FROM dbo.di_userSession s WITH(HOLDLOCK) JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=s.UserId JOIN dbo.di_userIdentity i WITH(HOLDLOCK) ON i.IdentityId=s.IdentityId AND i.UserId=s.UserId WHERE s.SessionId=@ActorSessionId AND s.SessionHash=@SessionHash AND s.UserId=@ActorUserId AND s.RevokedAtUTC IS NULL AND s.AbsoluteExpiresAtUTC>@Now AND s.IdleExpiresAtUTC>@Now AND s.UserSecurityVersion=u.SecurityVersion AND u.AccountStatus=2 AND i.IdentityStatus=2) THROW 51001,''ACCESS_SESSION_INVALID'',1;
    DECLARE @ScopeGroupId uniqueidentifier=@GroupId;
    DECLARE @AccessPermissions TABLE(PermissionCode varchar(100) PRIMARY KEY,DataScopeCode tinyint NOT NULL);
    ;WITH EligibleRoles AS (
      SELECT ur.RoleId,r.Priority FROM dbo.di_userRoleMapping ur WITH(HOLDLOCK) JOIN dbo.di_role r WITH(HOLDLOCK) ON r.RoleId=ur.RoleId AND r.IsActive=1
      WHERE ur.UserId=@ActorUserId AND ur.IsActive=1 AND ur.BeginsAtUTC<=@Now AND (ur.EndsAtUTC IS NULL OR ur.EndsAtUTC>@Now)
      AND ((ur.GrantScope=''A'' AND ur.RoleId IN (4,5)) OR (ur.GrantScope=''G'' AND ur.GroupId=@ScopeGroupId AND EXISTS (
        SELECT 1 FROM dbo.di_groupMembership m WITH(HOLDLOCK) JOIN dbo.di_group g WITH(HOLDLOCK) ON g.GroupId=m.GroupId JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=m.UserId LEFT JOIN dbo.di_userIdentity pi WITH(HOLDLOCK) ON pi.IdentityId=m.ProofIdentityId
        JOIN dbo.di_groupRoleMapping gr WITH(HOLDLOCK) ON gr.GroupId=m.GroupId AND gr.RoleId=ur.RoleId AND gr.IsActive=1
        WHERE m.MembershipId=ur.MembershipId AND m.UserId=ur.UserId AND ur.GrantMembershipEpoch=m.MembershipEpoch AND m.LocalState=1 AND m.ApprovalStatus IN (0,2,4) AND g.GroupStatus=2 AND (u.IsExternal=0 OR g.ProviderTypeId=3) AND (g.ProviderTypeId=3 OR (m.ProofStatus=1 AND m.ProofExpiresAtUTC>@Now AND m.ProofObservedAtUTC>=DATEADD(minute,-15,@Now) AND pi.IdentityStatus=2 AND pi.UserId=m.UserId AND pi.ProviderTypeId=g.ProviderTypeId AND ((g.ProviderTypeId=1 AND pi.ProviderNamespace=g.DirectoryKey) OR (g.ProviderTypeId=2 AND pi.ProviderNamespace IN (''https://accounts.google.com'',''accounts.google.com''))))))))
      AND (@ScopeGroupId IS NULL OR EXISTS (SELECT 1 FROM dbo.di_group g JOIN dbo.di_userAccount u ON u.UserId=@ActorUserId WHERE g.GroupId=@ScopeGroupId AND g.GroupStatus<>4 AND (u.IsExternal=0 OR g.ProviderTypeId=3)))
    ), Chosen AS (SELECT RoleId FROM EligibleRoles WHERE Priority=(SELECT MAX(Priority) FROM EligibleRoles))
    INSERT @AccessPermissions SELECT p.PermissionCode,MAX(rp.DataScopeCode) FROM Chosen c JOIN dbo.di_rolePermission rp WITH(HOLDLOCK) ON rp.RoleId=c.RoleId AND rp.IsActive=1 JOIN dbo.di_info_permission p WITH(HOLDLOCK) ON p.PermissionId=rp.PermissionId AND p.IsActive=1 GROUP BY p.PermissionCode;


    IF @Take NOT BETWEEN 1 AND 100 OR @MappingKind NOT IN (''R'',''S'',''C'') THROW 51002,''ACCESS_PAGE_OR_KIND_INVALID'',1;
    IF NOT EXISTS(SELECT 1 FROM @AccessPermissions WHERE PermissionCode IN (''POLICY.REGION'',''POLICY.RESOURCE'')) THROW 51003,''ACCESS_PERMISSION_DENIED'',1;

    -- #region Approved catalogue IDs and labels; no credentials or configuration bodies.
    IF @MappingKind=''C''
    BEGIN
      IF @CatalogKind NOT IN (''REGION'',''SUBREGION'',''CLIENT'',''DATABASE'',''STORAGE'',''DATABRICKS'',''SHAREPOINT'',''GDRIVE'') OR @CatalogKind IS NULL
        THROW 51002,''ACCESS_CATALOGUE_KIND_INVALID'',1;
      IF NOT EXISTS(SELECT 1 FROM @AccessPermissions WHERE PermissionCode=CASE WHEN @CatalogKind IN (''REGION'',''SUBREGION'',''CLIENT'') THEN ''POLICY.REGION'' ELSE ''POLICY.RESOURCE'' END)
        THROW 51003,''ACCESS_PERMISSION_DENIED'',1;
      SET @Search=LTRIM(RTRIM(ISNULL(@Search,N'''')));
      DECLARE @SearchPattern nvarchar(201)=REPLACE(REPLACE(REPLACE(REPLACE(@Search,N''\'',N''\\''),N''%'',N''\%''),N''_'',N''\_''),N''['',N''\['')+N''%'';
      IF @CatalogKind IN (''REGION'',''SUBREGION'',''CLIENT'',''DATABASE'',''STORAGE'',''DATABRICKS'')
        AND @AfterValue IS NOT NULL AND TRY_CONVERT(int,@AfterValue) IS NULL THROW 51002,''ACCESS_CATALOGUE_CURSOR_INVALID'',1;
      IF @CatalogKind IN (''SHAREPOINT'',''GDRIVE'') AND @AfterValue IS NOT NULL AND TRY_CONVERT(uniqueidentifier,@AfterValue) IS NULL THROW 51002,''ACCESS_CATALOGUE_CURSOR_INVALID'',1;
      IF @CatalogKind=''REGION''
        SELECT TOP(@Take) CONVERT(nvarchar(64),Id) AS Value,Name AS Label,NULL AS ParentValue
        FROM dbo.di_info_region WHERE active=1 AND (@AfterValue IS NULL OR Id>CONVERT(int,@AfterValue)) AND Name LIKE @SearchPattern ESCAPE N''\'' ORDER BY Id;
      IF @CatalogKind=''SUBREGION''
        SELECT TOP(@Take) CONVERT(nvarchar(64),Id) AS Value,Name AS Label,CONVERT(nvarchar(64),regionId) AS ParentValue
        FROM dbo.di_info_sub_region WHERE active=1 AND (@ParentId IS NULL OR regionId=@ParentId) AND (@AfterValue IS NULL OR Id>CONVERT(int,@AfterValue)) AND Name LIKE @SearchPattern ESCAPE N''\'' ORDER BY Id;
      IF @CatalogKind=''CLIENT''
        SELECT TOP(@Take) CONVERT(nvarchar(64),Id) AS Value,Name AS Label,NULL AS ParentValue
        FROM dbo.di_info_clientnames WHERE active=1 AND (@AfterValue IS NULL OR Id>CONVERT(int,@AfterValue)) AND Name LIKE @SearchPattern ESCAPE N''\'' ORDER BY Id;
      IF @CatalogKind=''DATABASE''
        SELECT TOP(@Take) CONVERT(nvarchar(64),id) AS Value,databaseName AS Label,NULL AS ParentValue
        FROM dbo.di_databaseConfiguration WHERE active=1 AND (@AfterValue IS NULL OR id>CONVERT(int,@AfterValue)) AND databaseName LIKE @SearchPattern ESCAPE N''\'' ORDER BY id;
      IF @CatalogKind=''STORAGE''
        SELECT TOP(@Take) CONVERT(nvarchar(64),storageAccountId) AS Value,displayName AS Label,NULL AS ParentValue
        FROM dbo.di_info_storageAccountDetails WHERE active=1 AND (@AfterValue IS NULL OR storageAccountId>CONVERT(int,@AfterValue)) AND displayName LIKE @SearchPattern ESCAPE N''\'' ORDER BY storageAccountId;
      IF @CatalogKind=''DATABRICKS''
        SELECT TOP(@Take) CONVERT(nvarchar(64),id) AS Value,instanceName AS Label,NULL AS ParentValue
        FROM dbo.di_info_databricksInstance WHERE active=1 AND (@AfterValue IS NULL OR id>CONVERT(int,@AfterValue)) AND instanceName LIKE @SearchPattern ESCAPE N''\'' ORDER BY id;
      IF @CatalogKind=''SHAREPOINT''
        SELECT TOP(@Take) CONVERT(nvarchar(64),applicationid) AS Value,displayname AS Label,NULL AS ParentValue
        FROM dbo.di_application WHERE isactive=1 AND deletedon IS NULL AND ISNULL(isdraft,0)=0 AND (@AfterValue IS NULL OR applicationid>CONVERT(uniqueidentifier,@AfterValue)) AND displayname LIKE @SearchPattern ESCAPE N''\'' ORDER BY applicationid;
      IF @CatalogKind=''GDRIVE''
        SELECT TOP(@Take) CONVERT(nvarchar(64),tenantid) AS Value,displayname AS Label,NULL AS ParentValue
        FROM dbo.di_gdrive_tenant WHERE isactive=1 AND ISNULL(isdraft,0)=0 AND (@AfterValue IS NULL OR tenantid>CONVERT(uniqueidentifier,@AfterValue)) AND displayname LIKE @SearchPattern ESCAPE N''\'' ORDER BY tenantid;
      RETURN;
    END;
    -- #endregion

    BEGIN TRY
    BEGIN TRANSACTION;
    DECLARE @ReadPolicyVersion bigint;
    SELECT @ReadPolicyVersion=PolicyVersion FROM dbo.di_group WITH(HOLDLOCK) WHERE GroupId=@GroupId;
    SELECT TOP(@Take) m.MappingId,m.GroupId,m.ScopeKind,m.ScopeKind AS ResourceKind,m.RegionId,m.SubRegionId,m.ClientId,
      m.DatabaseConfigurationId,m.StorageAccountRowId,m.DatabricksInstanceRowId,m.SharePointApplicationId,m.GoogleDriveTenantId,
      m.CanUse,m.CanManage,m.IsActive,m.RowVersion,r.Name AS RegionName,s.Name AS SubRegionName,c.Name AS ClientName,
      CASE m.ScopeKind WHEN ''DATABASE'' THEN db.databaseName WHEN ''STORAGE'' THEN st.displayName WHEN ''DATABRICKS'' THEN dt.instanceName
        WHEN ''SHAREPOINT'' THEN sp.displayname WHEN ''GDRIVE'' THEN gd.displayname END AS ResourceName
    FROM dbo.di_groupScopeMapping m
    LEFT JOIN dbo.di_info_region r ON r.Id=m.RegionId
    LEFT JOIN dbo.di_info_sub_region s ON s.Id=m.SubRegionId AND s.regionId=m.RegionId
    LEFT JOIN dbo.di_info_clientnames c ON c.Id=m.ClientId
    LEFT JOIN dbo.di_databaseConfiguration db ON db.id=m.DatabaseConfigurationId
    LEFT JOIN dbo.di_info_storageAccountDetails st ON st.storageAccountId=m.StorageAccountRowId
    LEFT JOIN dbo.di_info_databricksInstance dt ON dt.id=m.DatabricksInstanceRowId
    LEFT JOIN dbo.di_application sp ON sp.applicationid=m.SharePointApplicationId
    LEFT JOIN dbo.di_gdrive_tenant gd ON gd.tenantid=m.GoogleDriveTenantId
    WHERE m.GroupId=@GroupId AND m.IsActive=1 AND ((@MappingKind=''R'' AND m.ScopeKind=''REGION'') OR (@MappingKind=''S'' AND m.ScopeKind<>''REGION''))
      AND (@AfterMappingId IS NULL OR m.MappingId>@AfterMappingId) ORDER BY m.MappingId;

    SELECT @ReadPolicyVersion AS PolicyVersion;
    COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
      IF XACT_STATE()<>0 ROLLBACK TRANSACTION;
      THROW;
    END CATCH;

END;
';

 -- dbo.sel_accessProcessList
 EXEC sys.sp_executesql N'CREATE OR ALTER PROCEDURE dbo.sel_accessProcessList
    @ActorUserId uniqueidentifier,
    @ActorSessionId uniqueidentifier,
    @SessionHash binary(32),
    @ViewMode char(1)=''G'',
    @GroupId uniqueidentifier=NULL,
    @AfterProcessId nvarchar(100)=NULL,
    @Take int=50,
    @IncludeInactive bit=0
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    BEGIN TRY
    BEGIN TRANSACTION;
    DECLARE @Now datetime2(3)=SYSUTCDATETIME();
    IF NOT EXISTS (SELECT 1 FROM dbo.di_userSession s WITH(HOLDLOCK) JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=s.UserId JOIN dbo.di_userIdentity i WITH(HOLDLOCK) ON i.IdentityId=s.IdentityId AND i.UserId=s.UserId WHERE s.SessionId=@ActorSessionId AND s.SessionHash=@SessionHash AND s.UserId=@ActorUserId AND s.RevokedAtUTC IS NULL AND s.AbsoluteExpiresAtUTC>@Now AND s.IdleExpiresAtUTC>@Now AND s.UserSecurityVersion=u.SecurityVersion AND u.AccountStatus=2 AND i.IdentityStatus=2) THROW 51001,''ACCESS_SESSION_INVALID'',1;
    DECLARE @ScopeGroupId uniqueidentifier=@GroupId;
    DECLARE @AccessPermissions TABLE(PermissionCode varchar(100) PRIMARY KEY,DataScopeCode tinyint NOT NULL);
    ;WITH EligibleRoles AS (
      SELECT ur.RoleId,r.Priority FROM dbo.di_userRoleMapping ur WITH(HOLDLOCK) JOIN dbo.di_role r WITH(HOLDLOCK) ON r.RoleId=ur.RoleId AND r.IsActive=1
      WHERE ur.UserId=@ActorUserId AND ur.IsActive=1 AND ur.BeginsAtUTC<=@Now AND (ur.EndsAtUTC IS NULL OR ur.EndsAtUTC>@Now)
      AND ((ur.GrantScope=''A'' AND ur.RoleId IN (4,5)) OR (ur.GrantScope=''G'' AND ur.GroupId=@ScopeGroupId AND EXISTS (
        SELECT 1 FROM dbo.di_groupMembership m WITH(HOLDLOCK) JOIN dbo.di_group g WITH(HOLDLOCK) ON g.GroupId=m.GroupId JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=m.UserId LEFT JOIN dbo.di_userIdentity pi WITH(HOLDLOCK) ON pi.IdentityId=m.ProofIdentityId
        JOIN dbo.di_groupRoleMapping gr WITH(HOLDLOCK) ON gr.GroupId=m.GroupId AND gr.RoleId=ur.RoleId AND gr.IsActive=1
        WHERE m.MembershipId=ur.MembershipId AND m.UserId=ur.UserId AND ur.GrantMembershipEpoch=m.MembershipEpoch AND m.LocalState=1 AND m.ApprovalStatus IN (0,2,4) AND g.GroupStatus=2 AND (u.IsExternal=0 OR g.ProviderTypeId=3) AND (g.ProviderTypeId=3 OR (m.ProofStatus=1 AND m.ProofExpiresAtUTC>@Now AND m.ProofObservedAtUTC>=DATEADD(minute,-15,@Now) AND pi.IdentityStatus=2 AND pi.UserId=m.UserId AND pi.ProviderTypeId=g.ProviderTypeId AND ((g.ProviderTypeId=1 AND pi.ProviderNamespace=g.DirectoryKey) OR (g.ProviderTypeId=2 AND pi.ProviderNamespace IN (''https://accounts.google.com'',''accounts.google.com''))))))))
      AND (@ScopeGroupId IS NULL OR EXISTS (SELECT 1 FROM dbo.di_group g JOIN dbo.di_userAccount u ON u.UserId=@ActorUserId WHERE g.GroupId=@ScopeGroupId AND g.GroupStatus<>4 AND (u.IsExternal=0 OR g.ProviderTypeId=3)))
    ), Chosen AS (SELECT RoleId FROM EligibleRoles WHERE Priority=(SELECT MAX(Priority) FROM EligibleRoles))
    INSERT @AccessPermissions SELECT p.PermissionCode,MAX(rp.DataScopeCode) FROM Chosen c JOIN dbo.di_rolePermission rp WITH(HOLDLOCK) ON rp.RoleId=c.RoleId AND rp.IsActive=1 JOIN dbo.di_info_permission p WITH(HOLDLOCK) ON p.PermissionId=rp.PermissionId AND p.IsActive=1 GROUP BY p.PermissionCode;
    IF NOT EXISTS (SELECT 1 FROM @AccessPermissions WHERE PermissionCode=''PROCESS.LIST'') THROW 51003,''ACCESS_PERMISSION_DENIED'',1;


    -- #region Read-only business access: scope before projection, paging and aggregation
    DECLARE @DataScope tinyint=(SELECT DataScopeCode FROM @AccessPermissions WHERE PermissionCode=''PROCESS.LIST'');
    IF @ViewMode IS NULL OR @ViewMode NOT IN (''G'',''A'') OR (@ViewMode=''G'' AND @GroupId IS NULL) OR (@ViewMode=''A'' AND @GroupId IS NOT NULL) THROW 51002,''ACCESS_BUSINESS_VIEW_INVALID'',1;
    IF (@ViewMode=''A'' AND ISNULL(@DataScope,0)<3) OR ISNULL(@DataScope,0) NOT BETWEEN 1 AND 3 THROW 51003,''ACCESS_BUSINESS_SCOPE_DENIED'',1;
    CREATE TABLE #EligibleGroups(GroupId uniqueidentifier NOT NULL PRIMARY KEY,LegacySecurityGroupId varchar(200) NOT NULL);
    INSERT #EligibleGroups(GroupId,LegacySecurityGroupId)
      SELECT g.GroupId,g.LegacySecurityGroupId FROM dbo.di_group g
      JOIN dbo.di_info_securityGroup oldg ON oldg.id=g.LegacySecurityGroupRowId AND oldg.securityGroupId COLLATE Latin1_General_100_BIN2=g.LegacySecurityGroupId COLLATE Latin1_General_100_BIN2
      WHERE g.GroupStatus=2 AND oldg.active=1 AND (@ViewMode=''A'' OR g.GroupId=@GroupId)
        AND (g.ProviderTypeId=3 OR NOT EXISTS(SELECT 1 FROM dbo.di_userAccount WHERE UserId=@ActorUserId AND IsExternal=1));
    -- #endregion
    IF @Take IS NULL OR @Take NOT BETWEEN 1 AND 100 THROW 51002,''ACCESS_PAGE_SIZE_INVALID'',1;
    IF @IncludeInactive=1 AND NOT EXISTS(SELECT 1 FROM @AccessPermissions WHERE PermissionCode=''PROCESS.DISABLE'' AND DataScopeCode IN (2,3)) THROW 51003,''ACCESS_PERMISSION_DENIED'',1;
    DECLARE @AfterId bigint=TRY_CONVERT(bigint,@AfterProcessId);
    IF @AfterProcessId IS NOT NULL AND (@AfterId IS NULL OR @AfterId<1 OR @AfterProcessId LIKE ''%[^0-9]%'') THROW 51002,''ACCESS_CURSOR_INVALID'',1;

    SELECT TOP(@Take+1) p.id AS RowId,CONVERT(nvarchar(100),p.id) AS ProcessId,p.flpConfigurationId AS ConfigurationId,p.process_name AS ProcessName,p.Description,p.created_date AS CreatedAt,p.modified_date AS ModifiedAt,p.is_active AS IsActive,p.regionId AS RegionId,p.subRegionId AS SubRegionId,p.clientId AS ClientId,HASHBYTES(''SHA2_256'',CONVERT(varbinary(max),(SELECT p.process_name,p.Description,p.is_active,p.modified_date,p.regionId,p.subRegionId,p.clientId,p.sharePointApplicationId,p.sourcePath,p.destinationPath FOR JSON PATH,WITHOUT_ARRAY_WRAPPER,INCLUDE_NULL_VALUES))) AS StateVersion INTO #Page
      FROM dbo.di_flpConfiguration p WHERE (@AfterId IS NULL OR p.id>@AfterId) AND (p.is_active=1 OR (@IncludeInactive=1 AND p.is_active=0)) AND NOT EXISTS(SELECT 1 FROM dbo.di_flpConfiguration ambiguous WHERE ambiguous.flpConfigurationId=p.flpConfigurationId AND ambiguous.id<>p.id) AND EXISTS(
        SELECT 1 FROM #EligibleGroups eg
        JOIN dbo.di_flpConfigurationSecurityGroupMapping oldm ON oldm.securityGroupId=eg.LegacySecurityGroupId AND oldm.flpConfigurationId=p.flpConfigurationId AND oldm.active=1
        JOIN dbo.di_groupScopeMapping sm ON sm.GroupId=eg.GroupId AND sm.ScopeKind=''REGION'' AND sm.IsActive=1 AND sm.RegionId=p.regionId AND sm.ClientId=p.clientId AND CONVERT(varchar(55),sm.SubRegionId)=p.subRegionId
        JOIN dbo.di_info_region r ON r.Id=sm.RegionId AND r.active=1
        JOIN dbo.di_info_sub_region sr ON sr.Id=sm.SubRegionId AND sr.regionId=r.Id AND sr.active=1
        JOIN dbo.di_info_clientnames c ON c.Id=sm.ClientId AND c.active=1) AND (@DataScope<>1 OR EXISTS(SELECT 1 FROM dbo.di_userLegacyLink a JOIN dbo.di_userAccount owneru ON owneru.UserId=a.UserId JOIN dbo.di_AppUsers olduser ON olduser.Id=owneru.LegacyAppUserId AND olduser.LoginId COLLATE Latin1_General_100_BIN2=owneru.LegacyLoginId COLLATE Latin1_General_100_BIN2 WHERE a.UserId=@ActorUserId AND a.AliasAuthority=''TPDI'' AND a.AliasKind=2 AND a.IsActive=1 AND a.NormalizedAlias=UPPER(LTRIM(RTRIM(p.created_by))) COLLATE Latin1_General_100_BIN2)) ORDER BY p.id;
    SELECT TOP(@Take) ProcessId,ConfigurationId,ProcessName,Description,CreatedAt,ModifiedAt,IsActive,RegionId,SubRegionId,ClientId,StateVersion FROM #Page ORDER BY RowId;

    SELECT @Take AS Take,CONVERT(bit,CASE WHEN COUNT(*)>@Take THEN 1 ELSE 0 END) AS HasMore,
      CASE WHEN COUNT(*)>@Take THEN CONVERT(nvarchar(100),(SELECT MAX(RowId) FROM (SELECT TOP(@Take) RowId FROM #Page ORDER BY RowId) pageEnd)) ELSE NULL END AS NextCursor FROM #Page;

    COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
      IF XACT_STATE()<>0 ROLLBACK TRANSACTION;
      THROW;
    END CATCH;
END;
';

 COMMIT TRANSACTION;
 SELECT DB_NAME() AS DatabaseName,N'Remaining four procedures and source-request schema applied' AS Result;
 SELECT OBJECT_NAME(p.object_id) AS ProcedureName,p.name AS ParameterName,TYPE_NAME(p.user_type_id) AS DataType
 FROM sys.parameters p JOIN (VALUES
 (N'commit_accessIdentity',N'@CompanyDirectoryEligible'),
 (N'commit_accessPermissionCatalog',N'@Command'),(N'commit_accessPermissionCatalog',N'@Description'),
 (N'sel_accessGroupMappings',N'@CatalogKind'),(N'sel_accessGroupMappings',N'@Search'),
 (N'sel_accessGroupMappings',N'@ParentId'),(N'sel_accessGroupMappings',N'@AfterValue'),
 (N'sel_accessProcessList',N'@IncludeInactive')) expected(ProcedureName,ParameterName)
 ON p.object_id=OBJECT_ID(N'dbo.'+expected.ProcedureName) AND p.name=expected.ParameterName
 ORDER BY ProcedureName,ParameterName;
 SELECT N'dbo.di_sourceSetupRequest' AS TableName,OBJECT_ID(N'dbo.di_sourceSetupRequest',N'U') AS ObjectId,
 COL_LENGTH(N'dbo.di_info_permission',N'Description') AS PermissionDescriptionMaxBytes;
END TRY
BEGIN CATCH
 IF XACT_STATE()<>0 ROLLBACK TRANSACTION;
 THROW;
END CATCH;
