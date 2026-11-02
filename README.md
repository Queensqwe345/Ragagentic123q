-- Admin/RBAC: CREATE the five missing procedures only.
-- Prepared 2 November 2026 IST from current local reference definitions.
-- Select the intended UAT database before running; this file does not switch databases.
-- Requires compatible Access schema, existing business catalogue tables (including
-- di_sourceSetupRequest), and the existing access_api_executor role.
-- CREATE fails if a procedure already exists. No replacements or DROP statements.
-- Original module ANSI/quoted-identifier settings and EXECUTE grants are preserved.

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER OFF;
GO

CREATE PROCEDURE dbo.sel_accessApplicationView
 @ActorUserId uniqueidentifier, @ActorSessionId uniqueidentifier, @SessionHash binary(32),
 @View varchar(30), @ViewMode char(1)='G', @GroupId uniqueidentifier=NULL,
 @Page int=1, @Take int=20, @Search nvarchar(100)=NULL, @SearchFields varchar(300)=NULL, @Active bit=1,
 @From datetime2(3)=NULL, @To datetime2(3)=NULL,
 @ConfigurationId varchar(200)=NULL, @UploadId varchar(200)=NULL
AS
BEGIN
 SET NOCOUNT ON; SET XACT_ABORT ON;
 BEGIN TRY
 BEGIN TRANSACTION;
 DECLARE @Permission varchar(100)=CASE
   WHEN @View IN ('processes','extensions','dateformats') THEN 'PROCESS.LIST'
   WHEN @View IN ('status','filedetail') THEN 'STATUS.VIEW'
   WHEN @View='history' THEN 'HISTORY.VIEW'
   WHEN @View IN ('processcounts','filecounts','clientcounts','recent','uploads','utilization','regions') THEN 'DASHBOARD.VIEW' END;
 IF @Permission IS NULL OR @Page NOT BETWEEN 1 AND 10000 OR @Take NOT BETWEEN 1 AND 100
   THROW 51002,'ACCESS_APPLICATION_QUERY_INVALID',1;
 IF @SearchFields IS NOT NULL AND EXISTS(SELECT 1 FROM STRING_SPLIT(@SearchFields,',') WHERE value NOT IN('process','type','region','subregion','client','database','table','creator','ingestion','description','file','status')) THROW 51002,'ACCESS_APPLICATION_FILTER_INVALID',1;
 IF (@From IS NULL AND @To IS NOT NULL) OR (@To IS NULL AND @From IS NOT NULL)
   OR @From>=@To OR @To>DATEADD(day,366,@From) THROW 51002,'ACCESS_APPLICATION_RANGE_INVALID',1;
    DECLARE @Now datetime2(3)=SYSUTCDATETIME();
    IF NOT EXISTS (SELECT 1 FROM dbo.di_userSession s WITH(HOLDLOCK) JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=s.UserId JOIN dbo.di_userIdentity i WITH(HOLDLOCK) ON i.IdentityId=s.IdentityId AND i.UserId=s.UserId WHERE s.SessionId=@ActorSessionId AND s.SessionHash=@SessionHash AND s.UserId=@ActorUserId AND s.RevokedAtUTC IS NULL AND s.AbsoluteExpiresAtUTC>@Now AND s.IdleExpiresAtUTC>@Now AND s.UserSecurityVersion=u.SecurityVersion AND u.AccountStatus=2 AND i.IdentityStatus=2) THROW 51001,'ACCESS_SESSION_INVALID',1;
    DECLARE @ScopeGroupId uniqueidentifier=@GroupId;
    DECLARE @AccessPermissions TABLE(PermissionCode varchar(100) PRIMARY KEY,DataScopeCode tinyint NOT NULL);
    ;WITH EligibleRoles AS (
      SELECT ur.RoleId,r.Priority FROM dbo.di_userRoleMapping ur WITH(HOLDLOCK) JOIN dbo.di_role r WITH(HOLDLOCK) ON r.RoleId=ur.RoleId AND r.IsActive=1
      WHERE ur.UserId=@ActorUserId AND ur.IsActive=1 AND ur.BeginsAtUTC<=@Now AND (ur.EndsAtUTC IS NULL OR ur.EndsAtUTC>@Now)
      AND ((ur.GrantScope='A' AND ur.RoleId IN (4,5)) OR (ur.GrantScope='G' AND ur.GroupId=@ScopeGroupId AND EXISTS (
        SELECT 1 FROM dbo.di_groupMembership m WITH(HOLDLOCK) JOIN dbo.di_group g WITH(HOLDLOCK) ON g.GroupId=m.GroupId JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=m.UserId LEFT JOIN dbo.di_userIdentity pi WITH(HOLDLOCK) ON pi.IdentityId=m.ProofIdentityId
        JOIN dbo.di_groupRoleMapping gr WITH(HOLDLOCK) ON gr.GroupId=m.GroupId AND gr.RoleId=ur.RoleId AND gr.IsActive=1
        WHERE m.MembershipId=ur.MembershipId AND m.UserId=ur.UserId AND ur.GrantMembershipEpoch=m.MembershipEpoch AND m.LocalState=1 AND m.ApprovalStatus IN (0,2,4) AND g.GroupStatus=2 AND (u.IsExternal=0 OR g.ProviderTypeId=3) AND (g.ProviderTypeId=3 OR (m.ProofStatus=1 AND m.ProofExpiresAtUTC>@Now AND m.ProofObservedAtUTC>=DATEADD(minute,-15,@Now) AND pi.IdentityStatus=2 AND pi.UserId=m.UserId AND pi.ProviderTypeId=g.ProviderTypeId AND ((g.ProviderTypeId=1 AND pi.ProviderNamespace=g.DirectoryKey) OR (g.ProviderTypeId=2 AND pi.ProviderNamespace IN ('https://accounts.google.com','accounts.google.com'))))))))
      AND (@ScopeGroupId IS NULL OR EXISTS (SELECT 1 FROM dbo.di_group g JOIN dbo.di_userAccount u ON u.UserId=@ActorUserId WHERE g.GroupId=@ScopeGroupId AND g.GroupStatus<>4 AND (u.IsExternal=0 OR g.ProviderTypeId=3)))
    ), Chosen AS (SELECT RoleId FROM EligibleRoles WHERE Priority=(SELECT MAX(Priority) FROM EligibleRoles))
    INSERT @AccessPermissions SELECT p.PermissionCode,MAX(rp.DataScopeCode) FROM Chosen c JOIN dbo.di_rolePermission rp WITH(HOLDLOCK) ON rp.RoleId=c.RoleId AND rp.IsActive=1 JOIN dbo.di_info_permission p WITH(HOLDLOCK) ON p.PermissionId=rp.PermissionId AND p.IsActive=1 GROUP BY p.PermissionCode;
    IF NOT EXISTS (SELECT 1 FROM @AccessPermissions WHERE PermissionCode=@Permission) THROW 51003,'ACCESS_PERMISSION_DENIED',1;



    -- #region Read-only business access: scope before projection, paging and aggregation
    DECLARE @DataScope tinyint=(SELECT DataScopeCode FROM @AccessPermissions WHERE PermissionCode=@Permission);
    IF @ViewMode IS NULL OR @ViewMode NOT IN ('G','A') OR (@ViewMode='G' AND @GroupId IS NULL) OR (@ViewMode='A' AND @GroupId IS NOT NULL) THROW 51002,'ACCESS_BUSINESS_VIEW_INVALID',1;
    IF (@ViewMode='A' AND ISNULL(@DataScope,0)<3) OR ISNULL(@DataScope,0) NOT BETWEEN 1 AND 3 THROW 51003,'ACCESS_BUSINESS_SCOPE_DENIED',1;
    CREATE TABLE #EligibleGroups(GroupId uniqueidentifier NOT NULL PRIMARY KEY,LegacySecurityGroupId varchar(200) NOT NULL);
    INSERT #EligibleGroups(GroupId,LegacySecurityGroupId)
      SELECT g.GroupId,g.LegacySecurityGroupId FROM dbo.di_group g
      JOIN dbo.di_info_securityGroup oldg ON oldg.id=g.LegacySecurityGroupRowId AND oldg.securityGroupId COLLATE Latin1_General_100_BIN2=g.LegacySecurityGroupId COLLATE Latin1_General_100_BIN2
      WHERE g.GroupStatus=2 AND oldg.active=1 AND (@ViewMode='A' OR g.GroupId=@GroupId)
        AND (g.ProviderTypeId=3 OR NOT EXISTS(SELECT 1 FROM dbo.di_userAccount WHERE UserId=@ActorUserId AND IsExternal=1));
    -- #endregion

 -- A is an explicit application-wide read: only a live application role with All scope.
 -- G always retains the reviewed group/region/creator boundaries, including for administrators.
 IF @ViewMode='A' AND NOT EXISTS(SELECT 1 FROM dbo.di_userRoleMapping ur
   JOIN dbo.di_role r ON r.RoleId=ur.RoleId AND r.IsActive=1
   WHERE ur.UserId=@ActorUserId AND ur.GrantScope='A' AND ur.RoleId IN(4,5)
   AND ur.IsActive=1 AND ur.BeginsAtUTC<=@Now AND (ur.EndsAtUTC IS NULL OR ur.EndsAtUTC>@Now))
   THROW 51003,'ACCESS_APPLICATION_ALL_DENIED',1;
 IF @ViewMode='G' AND NOT EXISTS(SELECT 1 FROM dbo.di_groupMembership m
   JOIN dbo.di_group g ON g.GroupId=m.GroupId AND g.GroupStatus=2
   JOIN dbo.di_userAccount u ON u.UserId=m.UserId
   LEFT JOIN dbo.di_userIdentity pi ON pi.IdentityId=m.ProofIdentityId
   WHERE m.UserId=@ActorUserId AND m.GroupId=@GroupId AND m.LocalState=1 AND m.ApprovalStatus IN(0,2,4)
   AND (u.IsExternal=0 OR g.ProviderTypeId=3)
   AND (g.ProviderTypeId=3 OR (m.ProofStatus=1 AND m.ProofExpiresAtUTC>@Now
   AND m.ProofObservedAtUTC>=DATEADD(minute,-15,@Now) AND pi.IdentityStatus=2 AND pi.UserId=m.UserId
   AND pi.ProviderTypeId=g.ProviderTypeId AND ((g.ProviderTypeId=1 AND pi.ProviderNamespace=g.DirectoryKey)
   OR (g.ProviderTypeId=2 AND pi.ProviderNamespace IN('https://accounts.google.com','accounts.google.com'))))))
   THROW 51003,'ACCESS_APPLICATION_GROUP_DENIED',1;
 SELECT p.id INTO #Scope FROM dbo.di_flpConfiguration p WHERE
   NOT EXISTS(SELECT 1 FROM dbo.di_flpConfiguration ambiguous WHERE ambiguous.flpConfigurationId=p.flpConfigurationId AND ambiguous.id<>p.id) AND
   (@ViewMode='A' OR (NOT EXISTS(SELECT 1 FROM dbo.di_flpConfiguration ambiguous WHERE ambiguous.flpConfigurationId=p.flpConfigurationId AND ambiguous.id<>p.id) AND EXISTS(
        SELECT 1 FROM #EligibleGroups eg
        JOIN dbo.di_flpConfigurationSecurityGroupMapping oldm ON oldm.securityGroupId=eg.LegacySecurityGroupId AND oldm.flpConfigurationId=p.flpConfigurationId AND oldm.active=1
        JOIN dbo.di_groupScopeMapping sm ON sm.GroupId=eg.GroupId AND sm.ScopeKind='REGION' AND sm.IsActive=1 AND sm.RegionId=p.regionId AND sm.ClientId=p.clientId AND CONVERT(varchar(55),sm.SubRegionId)=p.subRegionId
        JOIN dbo.di_info_region r ON r.Id=sm.RegionId AND r.active=1
        JOIN dbo.di_info_sub_region sr ON sr.Id=sm.SubRegionId AND sr.regionId=r.Id AND sr.active=1
        JOIN dbo.di_info_clientnames c ON c.Id=sm.ClientId AND c.active=1))) AND (@DataScope<>1 OR EXISTS(SELECT 1 FROM dbo.di_userLegacyLink a JOIN dbo.di_userAccount owneru ON owneru.UserId=a.UserId JOIN dbo.di_AppUsers olduser ON olduser.Id=owneru.LegacyAppUserId AND olduser.LoginId COLLATE Latin1_General_100_BIN2=owneru.LegacyLoginId COLLATE Latin1_General_100_BIN2 WHERE a.UserId=@ActorUserId AND a.AliasAuthority='TPDI' AND a.AliasKind=2 AND a.IsActive=1 AND a.NormalizedAlias=UPPER(LTRIM(RTRIM(p.created_by))) COLLATE Latin1_General_100_BIN2));
 CREATE UNIQUE CLUSTERED INDEX IX_Scope ON #Scope(id);
 DECLARE @Json nvarchar(max),@Total int,@Month int=MONTH(@Now),@MonthName nvarchar(30)=DATENAME(month,@Now);
 IF @View='processes'
 BEGIN
   SELECT p.id,p.flpConfigurationId AS configurationId,p.process_name AS processName,
     p.sender_communication_email AS senderEmail,p.created_by AS createdBy,p.loginid AS loginId,
     p.processTypeId,p.regionId,p.subRegionId,CONVERT(varchar(10),p.created_date,101) AS createdDate,
     p.region AS regionName,p.subRegion AS subRegionName,p.clientName,
     pt.processTypeName AS processTypeName,CONVERT(varchar(10),p.modified_date,101) AS updatedOn,p.updatedByName AS updatedBy,
     p.multisheet AS multiSheet,p.dataSourceTypeId,p.Description AS description,
     ctm.tabName,ctm.tableName,dbc.databaseName,p.fileProcessingServerTypeId AS ingestionTypeId,fpst.serverName AS ingestionType
     INTO #Processes FROM dbo.di_flpConfiguration p JOIN #Scope sc ON sc.id=p.id
     LEFT JOIN dbo.di_info_processType pt ON pt.processTypeId=p.processTypeId
     LEFT JOIN dbo.di_info_FileProcessingServerType fpst ON fpst.flpServerTypeId=p.fileProcessingServerTypeId
     OUTER APPLY(SELECT m.tabName,m.tableName,m.databaseConfigurationId FROM dbo.di_configurationTableMapping m
       WHERE m.flpConfigurationId=p.flpConfigurationId AND m.active=1 AND ISNULL(m.ignoreSheet,0)=0) ctm
     LEFT JOIN dbo.di_databaseConfiguration dbc ON dbc.id=ctm.databaseConfigurationId
     WHERE p.is_active=@Active AND (@Search IS NULL OR EXISTS(SELECT 1 FROM (VALUES
         ('process',CONVERT(nvarchar(max),p.process_name)),('type',pt.processTypeName),('region',p.region),('subregion',p.subRegion),('client',p.clientName),
         ('database',dbc.databaseName),('table',ctm.tableName),('creator',p.userName),('ingestion',fpst.serverName),('description',p.Description)
       ) searchColumns(field,value) WHERE (@SearchFields IS NULL OR searchColumns.field IN(SELECT value FROM STRING_SPLIT(@SearchFields,','))) AND CHARINDEX(@Search,searchColumns.value)>0))
       AND (@From IS NULL OR p.created_date>=@From) AND (@To IS NULL OR p.created_date<@To);
   SELECT @Total=COUNT(*) FROM #Processes;
   SET @Json=(SELECT JSON_QUERY((SELECT *,ROW_NUMBER() OVER(ORDER BY id DESC,tabName) AS rowNo FROM #Processes ORDER BY id DESC,tabName
     OFFSET (@Page-1)*@Take ROWS FETCH NEXT @Take ROWS ONLY FOR JSON PATH)) AS response,@Total AS totalCount FOR JSON PATH,WITHOUT_ARRAY_WRAPPER);
 END
 ELSE IF @View='processcounts'
   SET @Json=(SELECT COUNT(*) AS processRowCount,COUNT(CASE WHEN p.created_date>=DATEFROMPARTS(YEAR(@Now),@Month,1) THEN 1 END) AS newProcessCount,
     @Month AS currentMonth,@MonthName AS currentMonthName FROM dbo.di_flpConfiguration p JOIN #Scope s ON s.id=p.id WHERE p.is_active=1 FOR JSON PATH,WITHOUT_ARRAY_WRAPPER);
 ELSE IF @View='clientcounts'
   SET @Json=(SELECT COUNT(DISTINCT p.clientId) AS totalClients,COUNT(DISTINCT CASE WHEN c.active=1 THEN p.clientId END) AS activeClients,
     @Month AS currentMonth,@MonthName AS currentMonthName FROM dbo.di_flpConfiguration p JOIN #Scope s ON s.id=p.id
     JOIN dbo.di_info_clientnames c ON c.id=p.clientId WHERE p.is_active=1 FOR JSON PATH,WITHOUT_ARRAY_WRAPPER);
 ELSE IF @View NOT IN('extensions','dateformats')
 BEGIN
   SELECT uf.id,uf.uploadFileId,uf.flpConfigurationId AS configurationId,p.process_name AS processName,
     uf.fileName,uf.creationDateTime,uf.updationDateTime,uf.flpProcessStatusId AS processStatusId,
     (SELECT MAX(statusName) FROM dbo.di_info_flpProcessStatus WHERE statusCode=uf.flpProcessStatusId AND active=1) AS processStatusName,
     p.clientId,p.clientName,p.regionId,p.region AS regionName,p.subRegion AS subRegionName,p.loginid AS loginId,p.processTypeId,p.fileProcessingServerTypeId,
     uf.UploadedBy AS createdBy,p.Description,ctm.tableName,ctm.tabName,dbc.databaseName
     INTO #Files FROM dbo.di_uploadedFile uf JOIN dbo.di_flpConfiguration p ON p.flpConfigurationId=uf.flpConfigurationId
     JOIN #Scope s ON s.id=p.id
     OUTER APPLY(SELECT TOP(1) m.tableName,m.tabName,m.databaseConfigurationId FROM dbo.di_configurationTableMapping m
       WHERE m.flpConfigurationId=p.flpConfigurationId AND m.active=1 AND ISNULL(m.ignoreSheet,0)=0 ORDER BY m.id) ctm
     LEFT JOIN dbo.di_databaseConfiguration dbc ON dbc.id=ctm.databaseConfigurationId
     WHERE uf.active=1 AND p.is_active=1 AND (@From IS NULL OR uf.creationDateTime>=@From) AND (@To IS NULL OR uf.creationDateTime<@To)
       AND (@ConfigurationId IS NULL OR uf.flpConfigurationId=@ConfigurationId)
       AND (@UploadId IS NULL OR CONVERT(varchar(200),uf.uploadFileId)=@UploadId)
       AND (@Search IS NULL OR CHARINDEX(@Search,uf.fileName)>0 OR CHARINDEX(@Search,p.process_name)>0)
       AND (@DataScope<>1 OR EXISTS(SELECT 1 FROM dbo.di_userLegacyLink a JOIN dbo.di_userAccount owneru ON owneru.UserId=a.UserId JOIN dbo.di_AppUsers olduser ON olduser.Id=owneru.LegacyAppUserId AND olduser.LoginId COLLATE Latin1_General_100_BIN2=owneru.LegacyLoginId COLLATE Latin1_General_100_BIN2 WHERE a.UserId=@ActorUserId AND a.AliasAuthority='TPDI' AND a.AliasKind=3 AND a.IsActive=1 AND a.NormalizedAlias=UPPER(LTRIM(RTRIM(uf.UploadedBy))) COLLATE Latin1_General_100_BIN2));
   IF @View='filecounts'
     SET @Json=(SELECT COUNT(*) AS totalUploadedFiles,COUNT(CASE WHEN processStatusId=2 THEN 1 END) AS successCount,
       COUNT(CASE WHEN processStatusId IN(3,4) THEN 1 END) AS failureCount,
       COUNT(CASE WHEN creationDateTime>=DATEFROMPARTS(YEAR(@Now),@Month,1) THEN 1 END) AS newFileProcessCount,
       @Month AS currentMonth,@MonthName AS currentMonthName FROM #Files FOR JSON PATH,WITHOUT_ARRAY_WRAPPER);
   ELSE IF @View='recent'
     SET @Json=(SELECT TOP(@Take) configurationId,processName,uploadFileId,fileName,creationDateTime,processStatusId,processStatusName FROM #Files ORDER BY id DESC FOR JSON PATH);
   ELSE IF @View='uploads'
     SET @Json=(SELECT f.processTypeId,MAX(pt.processTypeName) AS processType,COUNT(*) AS totalUploadedFiles FROM #Files f
       LEFT JOIN dbo.di_info_processType pt ON pt.processTypeId=f.processTypeId GROUP BY f.processTypeId FOR JSON PATH);
   ELSE IF @View='utilization'
     SET @Json=(SELECT COUNT(*) AS totalFileCount,MONTH(creationDateTime) AS month,DATENAME(month,creationDateTime) AS monthName,clientId,MAX(clientName) AS clientName
       FROM #Files GROUP BY YEAR(creationDateTime),MONTH(creationDateTime),DATENAME(month,creationDateTime),clientId FOR JSON PATH);
   ELSE IF @View='regions'
     SET @Json=(SELECT regionId,MAX(regionName) AS regionName,COUNT(*) AS totalFileCount FROM #Files GROUP BY regionId FOR JSON PATH);
   ELSE IF @View='history'
   BEGIN
     SELECT @Total=COUNT(*) FROM #Files;
     SET @Json=(SELECT JSON_QUERY((SELECT *,processStatusName AS statusName,uploadFileId AS fileId,creationDateTime AS createdDate,creationDateTime AS startTime,updationDateTime AS endTime
       FROM #Files ORDER BY id DESC OFFSET (@Page-1)*@Take ROWS FETCH NEXT @Take ROWS ONLY FOR JSON PATH)) AS response,
       @Total AS totalCount FOR JSON PATH,WITHOUT_ARRAY_WRAPPER);
   END
   ELSE IF @View='status'
     SET @Json=(SELECT c.clientId,MAX(c.clientName) AS clientName,JSON_QUERY((SELECT p.configurationId AS flpConfigurationID,MAX(p.processName) AS flpConfigurationName,
       JSON_QUERY((SELECT TOP(@Take) f.uploadFileId,f.fileName AS uploadFileName,f.creationDateTime AS fileCreationDate,f.processStatusId AS fileProcessStatusId,
         f.processStatusName AS fileProcessstatusName,f.databaseName,f.tableName,f.tabName,f.fileProcessingServerTypeId FROM #Files f
         WHERE f.configurationId=p.configurationId ORDER BY f.id DESC FOR JSON PATH)) AS uploadedFiles
       FROM #Files p WHERE p.clientId=c.clientId GROUP BY p.configurationId FOR JSON PATH)) AS fileConfigurationStatusList
       FROM #Files c GROUP BY c.clientId FOR JSON PATH);
   ELSE IF @View='filedetail'
     SET @Json=(SELECT TOP(1) configurationId AS flpConfigurationID,uploadFileId AS uploadFileID,fileName AS uploadFile,databaseName,tableName,Description,tabName,
       JSON_QUERY((SELECT ls.statusName,ls.statusName AS logStatusName,st.flpFileLogStatusId,
         st.activityProcessStatusId AS processStatusId,aps.statusName AS processStatusName,
         st.creationDateTime AS statusStartTime,st.updationDateTime AS statusCompletionTime,
         DATEDIFF_BIG(millisecond,st.creationDateTime,st.updationDateTime)/1000.0 AS durationInSeconds,st.tabName
         FROM dbo.di_flpFileUploadStatus st
         JOIN dbo.di_info_flpActivityLogStatus ls ON ls.flpFileLogStatusId=st.flpFileLogStatusId AND ls.active=1
         JOIN dbo.di_info_flpActivityProcessStatus aps ON aps.activityProcessStatusId=st.activityProcessStatusId
         WHERE st.flpConfigurationId=#Files.configurationId AND st.uploadFileId=#Files.uploadFileId AND st.active=1
         ORDER BY ls.sequenceNo,st.id FOR JSON PATH)) AS fileStatus
       FROM #Files ORDER BY id DESC FOR JSON PATH,WITHOUT_ARRAY_WRAPPER);
 END
 -- These reviewed display catalogues contain no credentials or connection strings.
 ELSE IF @View='extensions' SET @Json=(SELECT id,fileExtension FROM dbo.di_info_FileExtensionName WHERE isActive=1 FOR JSON PATH);
 ELSE IF @View='dateformats' SET @Json=(SELECT id,formatId,format,apiFormat,formatDataTypeId,DisplayOnLandingLayer FROM dbo.di_info_datetimeFormat WHERE active=1 FOR JSON PATH);
 SELECT COALESCE(@Json,CASE WHEN @View IN('filedetail','processcounts','filecounts','clientcounts') THEN '{}' ELSE '[]' END) AS Payload;
 COMMIT TRANSACTION;
 END TRY BEGIN CATCH
   IF XACT_STATE()<>0 ROLLBACK TRANSACTION;
   THROW;
 END CATCH
END;
GO

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

CREATE PROCEDURE dbo.sel_accessHierarchy
 @ActorUserId uniqueidentifier,@ActorSessionId uniqueidentifier,@SessionHash binary(32),
 @GroupId uniqueidentifier,@Kind varchar(12),@RegionId int=NULL,@SubRegionId int=NULL,@AfterId int=NULL,@Take int=100
AS
BEGIN
 SET NOCOUNT ON;
 SET XACT_ABORT ON;
 DECLARE @Now datetime2(3)=SYSUTCDATETIME();
 IF NOT EXISTS(SELECT 1 FROM dbo.di_userSession se JOIN dbo.di_userAccount u ON u.UserId=se.UserId JOIN dbo.di_userIdentity i ON i.IdentityId=se.IdentityId AND i.UserId=u.UserId
  WHERE se.SessionId=@ActorSessionId AND se.UserId=@ActorUserId AND se.SessionHash=@SessionHash AND se.RevokedAtUTC IS NULL
   AND se.AbsoluteExpiresAtUTC>@Now AND se.IdleExpiresAtUTC>@Now AND se.UserSecurityVersion=u.SecurityVersion AND u.AccountStatus=2 AND i.IdentityStatus=2)
  THROW 51001,'ACCESS_SESSION_INVALID',1;
 IF @GroupId IS NULL OR @Kind NOT IN('REGION','SUBREGION','CLIENT') OR @Take NOT BETWEEN 1 AND 100 OR ISNULL(@AfterId,1)<1
  OR (@Kind='REGION' AND (@RegionId IS NOT NULL OR @SubRegionId IS NOT NULL))
  OR (@Kind IN('SUBREGION','CLIENT') AND ISNULL(@RegionId,0)<1) OR (@Kind='SUBREGION' AND @SubRegionId IS NOT NULL)
  OR (@SubRegionId IS NOT NULL AND @SubRegionId<1) THROW 51002,'ACCESS_HIERARCHY_QUERY_INVALID',1;
 -- Lookup choices are approved membership scope, never the administrator's global catalogue.
 IF NOT EXISTS(SELECT 1 FROM dbo.di_groupMembership m JOIN dbo.di_group g ON g.GroupId=m.GroupId
  JOIN dbo.di_userAccount u ON u.UserId=m.UserId LEFT JOIN dbo.di_userIdentity pi ON pi.IdentityId=m.ProofIdentityId
  WHERE m.UserId=@ActorUserId AND m.GroupId=@GroupId AND m.LocalState=1 AND m.ApprovalStatus IN(0,2,4) AND g.GroupStatus=2
   AND (u.IsExternal=0 OR g.ProviderTypeId=3)
   AND (g.ProviderTypeId=3 OR (m.ProofStatus=1 AND m.ProofExpiresAtUTC>@Now AND m.ProofObservedAtUTC>=DATEADD(minute,-15,@Now)
    AND pi.IdentityStatus=2 AND pi.UserId=m.UserId AND pi.ProviderTypeId=g.ProviderTypeId
    AND ((g.ProviderTypeId=1 AND pi.ProviderNamespace=g.DirectoryKey) OR (g.ProviderTypeId=2 AND pi.ProviderNamespace IN('https://accounts.google.com','accounts.google.com'))))))
  THROW 51003,'ACCESS_MEMBERSHIP_REQUIRED',1;
 ;WITH Allowed AS (
  SELECT m.RegionId,r.Name RegionName,m.SubRegionId,s.Name SubRegionName,m.ClientId,c.Name ClientName
  FROM dbo.di_groupScopeMapping m JOIN dbo.di_info_region r ON r.Id=m.RegionId AND r.active=1
  JOIN dbo.di_info_sub_region s ON s.Id=m.SubRegionId AND s.regionId=m.RegionId AND s.active=1
  JOIN dbo.di_info_clientnames c ON c.Id=m.ClientId AND c.active=1
  WHERE m.GroupId=@GroupId AND m.ScopeKind='REGION' AND m.IsActive=1
 ), Choices AS (
  SELECT RegionId Id,RegionName Label,CONVERT(int,NULL) ParentId FROM Allowed WHERE @Kind='REGION'
  UNION ALL SELECT SubRegionId,SubRegionName,RegionId FROM Allowed WHERE @Kind='SUBREGION' AND RegionId=@RegionId
  UNION ALL SELECT ClientId,ClientName,SubRegionId FROM Allowed WHERE @Kind='CLIENT' AND RegionId=@RegionId AND (@SubRegionId IS NULL OR SubRegionId=@SubRegionId)
 )
 SELECT TOP(@Take) CONVERT(nvarchar(64),Id) AS Value,Label,CONVERT(nvarchar(64),MIN(ParentId)) AS ParentValue
 FROM Choices WHERE @AfterId IS NULL OR Id>@AfterId GROUP BY Id,Label ORDER BY Id;
END;
GO

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

CREATE PROCEDURE dbo.sel_accessSources
    @ActorUserId uniqueidentifier,
    @ActorSessionId uniqueidentifier,
    @SessionHash binary(32),
    @GroupId uniqueidentifier,
    @Mode char(1)='R',
    @AfterId bigint=NULL,
    @Take int=50
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @Now datetime2(3)=SYSUTCDATETIME();
    IF NOT EXISTS (SELECT 1 FROM dbo.di_userSession s WITH(HOLDLOCK) JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=s.UserId JOIN dbo.di_userIdentity i WITH(HOLDLOCK) ON i.IdentityId=s.IdentityId AND i.UserId=s.UserId WHERE s.SessionId=@ActorSessionId AND s.SessionHash=@SessionHash AND s.UserId=@ActorUserId AND s.RevokedAtUTC IS NULL AND s.AbsoluteExpiresAtUTC>@Now AND s.IdleExpiresAtUTC>@Now AND s.UserSecurityVersion=u.SecurityVersion AND u.AccountStatus=2 AND i.IdentityStatus=2) THROW 51001,'ACCESS_SESSION_INVALID',1;
    DECLARE @ScopeGroupId uniqueidentifier=@GroupId;
    DECLARE @AccessPermissions TABLE(PermissionCode varchar(100) PRIMARY KEY,DataScopeCode tinyint NOT NULL);
    ;WITH EligibleRoles AS (
      SELECT ur.RoleId,r.Priority FROM dbo.di_userRoleMapping ur WITH(HOLDLOCK) JOIN dbo.di_role r WITH(HOLDLOCK) ON r.RoleId=ur.RoleId AND r.IsActive=1
      WHERE ur.UserId=@ActorUserId AND ur.IsActive=1 AND ur.BeginsAtUTC<=@Now AND (ur.EndsAtUTC IS NULL OR ur.EndsAtUTC>@Now)
      AND ((ur.GrantScope='A' AND ur.RoleId IN (4,5)) OR (ur.GrantScope='G' AND ur.GroupId=@ScopeGroupId AND EXISTS (
        SELECT 1 FROM dbo.di_groupMembership m WITH(HOLDLOCK) JOIN dbo.di_group g WITH(HOLDLOCK) ON g.GroupId=m.GroupId JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=m.UserId LEFT JOIN dbo.di_userIdentity pi WITH(HOLDLOCK) ON pi.IdentityId=m.ProofIdentityId
        JOIN dbo.di_groupRoleMapping gr WITH(HOLDLOCK) ON gr.GroupId=m.GroupId AND gr.RoleId=ur.RoleId AND gr.IsActive=1
        WHERE m.MembershipId=ur.MembershipId AND m.UserId=ur.UserId AND ur.GrantMembershipEpoch=m.MembershipEpoch AND m.LocalState=1 AND m.ApprovalStatus IN (0,2,4) AND g.GroupStatus=2 AND (u.IsExternal=0 OR g.ProviderTypeId=3) AND (g.ProviderTypeId=3 OR (m.ProofStatus=1 AND m.ProofExpiresAtUTC>@Now AND m.ProofObservedAtUTC>=DATEADD(minute,-15,@Now) AND pi.IdentityStatus=2 AND pi.UserId=m.UserId AND pi.ProviderTypeId=g.ProviderTypeId AND ((g.ProviderTypeId=1 AND pi.ProviderNamespace=g.DirectoryKey) OR (g.ProviderTypeId=2 AND pi.ProviderNamespace IN ('https://accounts.google.com','accounts.google.com'))))))))
      AND (@ScopeGroupId IS NULL OR EXISTS (SELECT 1 FROM dbo.di_group g JOIN dbo.di_userAccount u ON u.UserId=@ActorUserId WHERE g.GroupId=@ScopeGroupId AND g.GroupStatus<>4 AND (u.IsExternal=0 OR g.ProviderTypeId=3)))
    ), Chosen AS (SELECT RoleId FROM EligibleRoles WHERE Priority=(SELECT MAX(Priority) FROM EligibleRoles))
    INSERT @AccessPermissions SELECT p.PermissionCode,MAX(rp.DataScopeCode) FROM Chosen c JOIN dbo.di_rolePermission rp WITH(HOLDLOCK) ON rp.RoleId=c.RoleId AND rp.IsActive=1 JOIN dbo.di_info_permission p WITH(HOLDLOCK) ON p.PermissionId=rp.PermissionId AND p.IsActive=1 GROUP BY p.PermissionCode;


    IF @Take NOT BETWEEN 1 AND 100 OR @Mode NOT IN ('C','R','S') OR @GroupId IS NULL THROW 51002,'ACCESS_SOURCE_QUERY_INVALID',1;
    DECLARE @CanManage bit=CASE WHEN EXISTS(SELECT 1 FROM @AccessPermissions WHERE PermissionCode='SOURCE.MANAGE' AND DataScopeCode=4) THEN 1 ELSE 0 END;
    IF @Mode='S'
    BEGIN
      IF @CanManage=0 AND NOT EXISTS(SELECT 1 FROM @AccessPermissions WHERE PermissionCode IN ('PROCESS.CREATE','PROCESS.EXECUTE','FILE.UPLOAD') AND DataScopeCode IN (2,3)) THROW 51003,'ACCESS_PERMISSION_DENIED',1;
      SELECT TOP(@Take) m.MappingId,m.RegionId,m.SubRegionId,m.ClientId,r.Name AS RegionName,s.Name AS SubRegionName,c.Name AS ClientName
      FROM dbo.di_groupScopeMapping m JOIN dbo.di_info_region r ON r.Id=m.RegionId AND r.active=1 JOIN dbo.di_info_sub_region s ON s.Id=m.SubRegionId AND s.regionId=r.Id AND s.active=1 JOIN dbo.di_info_clientnames c ON c.Id=m.ClientId AND c.active=1
      WHERE m.GroupId=@GroupId AND m.ScopeKind='REGION' AND m.IsActive=1 AND (@AfterId IS NULL OR m.MappingId>@AfterId) ORDER BY m.MappingId;
      RETURN;
    END;
    IF @Mode='C'
    BEGIN
      IF @CanManage=0 AND NOT EXISTS(SELECT 1 FROM @AccessPermissions WHERE PermissionCode IN ('PROCESS.CREATE','PROCESS.EXECUTE','FILE.UPLOAD') AND DataScopeCode IN (2,3)) THROW 51003,'ACCESS_PERMISSION_DENIED',1;
      SELECT TOP(@Take) m.MappingId,m.ScopeKind AS SourceKind,
        CASE WHEN m.ScopeKind='SHAREPOINT' THEN CONVERT(nvarchar(64),sp.applicationid) ELSE CONVERT(nvarchar(64),gd.tenantid) END AS ResourceId,
        CASE WHEN m.ScopeKind='SHAREPOINT' THEN sp.displayname ELSE gd.displayname END AS DisplayName,m.CanUse,m.CanManage
      FROM dbo.di_groupScopeMapping m
      LEFT JOIN dbo.di_application sp ON m.ScopeKind='SHAREPOINT' AND sp.applicationid=m.SharePointApplicationId AND sp.isactive=1 AND sp.deletedon IS NULL AND ISNULL(sp.isdraft,0)=0
      LEFT JOIN dbo.di_gdrive_tenant gd ON m.ScopeKind='GDRIVE' AND gd.tenantid=m.GoogleDriveTenantId AND gd.isactive=1 AND ISNULL(gd.isdraft,0)=0
      WHERE m.GroupId=@GroupId AND m.IsActive=1 AND m.ScopeKind IN ('SHAREPOINT','GDRIVE') AND (m.CanUse=1 OR (@CanManage=1 AND m.CanManage=1))
        AND (sp.applicationid IS NOT NULL OR gd.tenantid IS NOT NULL) AND (@AfterId IS NULL OR m.MappingId>@AfterId) ORDER BY m.MappingId;
      RETURN;
    END;
    SELECT TOP(@Take) r.RequestId,r.GroupId,r.RequestedByUserId,u.DisplayName AS RequestedByName,r.SourceKind,r.DisplayName,r.LocationUrl,r.Details,r.RegionId,r.SubRegionId,r.ClientId,
      r.RequestStatus,r.ResourceId,r.ResolutionNote,r.CreatedAtUTC,r.UpdatedAtUTC,r.RowVersion
    FROM dbo.di_sourceSetupRequest r JOIN dbo.di_userAccount u ON u.UserId=r.RequestedByUserId
    WHERE r.GroupId=@GroupId AND (@CanManage=1 OR r.RequestedByUserId=@ActorUserId) AND (@AfterId IS NULL OR r.RequestId>@AfterId) ORDER BY r.RequestId;

END;
GO

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

CREATE PROCEDURE dbo.commit_accessSourceRequest
    @ActorUserId uniqueidentifier,
    @ActorSessionId uniqueidentifier,
    @SessionHash binary(32),
    @OperationId uniqueidentifier,
    @RequestHash binary(32),
    @CorrelationId uniqueidentifier,
    @ExpectedRowVersion binary(8)=NULL,
    @Command varchar(12),
    @GroupId uniqueidentifier,
    @RequestId bigint=NULL,
    @SourceKind varchar(16)=NULL,
    @DisplayName nvarchar(120)=NULL,
    @LocationUrl nvarchar(512)=NULL,
    @Details nvarchar(1000)=NULL,
    @RegionId int=NULL,
    @SubRegionId int=NULL,
    @ClientId int=NULL,
    @ResourceId nvarchar(64)=NULL,
    @ResolutionNote nvarchar(1000)=NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @Now datetime2(3)=SYSUTCDATETIME();
    IF @OperationId IS NULL OR @RequestHash IS NULL OR @CorrelationId IS NULL THROW 51002,'ACCESS_COMMAND_METADATA_REQUIRED',1;
    BEGIN TRY
      BEGIN TRANSACTION;
    IF NOT EXISTS (SELECT 1 FROM dbo.di_userSession s WITH(HOLDLOCK) JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=s.UserId JOIN dbo.di_userIdentity i WITH(HOLDLOCK) ON i.IdentityId=s.IdentityId AND i.UserId=s.UserId WHERE s.SessionId=@ActorSessionId AND s.SessionHash=@SessionHash AND s.UserId=@ActorUserId AND s.RevokedAtUTC IS NULL AND s.AbsoluteExpiresAtUTC>@Now AND s.IdleExpiresAtUTC>@Now AND s.UserSecurityVersion=u.SecurityVersion AND u.AccountStatus=2 AND i.IdentityStatus=2) THROW 51001,'ACCESS_SESSION_INVALID',1;
    DECLARE @ScopeGroupId uniqueidentifier=@GroupId;
    DECLARE @AccessPermissions TABLE(PermissionCode varchar(100) PRIMARY KEY,DataScopeCode tinyint NOT NULL);
    ;WITH EligibleRoles AS (
      SELECT ur.RoleId,r.Priority FROM dbo.di_userRoleMapping ur WITH(HOLDLOCK) JOIN dbo.di_role r WITH(HOLDLOCK) ON r.RoleId=ur.RoleId AND r.IsActive=1
      WHERE ur.UserId=@ActorUserId AND ur.IsActive=1 AND ur.BeginsAtUTC<=@Now AND (ur.EndsAtUTC IS NULL OR ur.EndsAtUTC>@Now)
      AND ((ur.GrantScope='A' AND ur.RoleId IN (4,5)) OR (ur.GrantScope='G' AND ur.GroupId=@ScopeGroupId AND EXISTS (
        SELECT 1 FROM dbo.di_groupMembership m WITH(HOLDLOCK) JOIN dbo.di_group g WITH(HOLDLOCK) ON g.GroupId=m.GroupId JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=m.UserId LEFT JOIN dbo.di_userIdentity pi WITH(HOLDLOCK) ON pi.IdentityId=m.ProofIdentityId
        JOIN dbo.di_groupRoleMapping gr WITH(HOLDLOCK) ON gr.GroupId=m.GroupId AND gr.RoleId=ur.RoleId AND gr.IsActive=1
        WHERE m.MembershipId=ur.MembershipId AND m.UserId=ur.UserId AND ur.GrantMembershipEpoch=m.MembershipEpoch AND m.LocalState=1 AND m.ApprovalStatus IN (0,2,4) AND g.GroupStatus=2 AND (u.IsExternal=0 OR g.ProviderTypeId=3) AND (g.ProviderTypeId=3 OR (m.ProofStatus=1 AND m.ProofExpiresAtUTC>@Now AND m.ProofObservedAtUTC>=DATEADD(minute,-15,@Now) AND pi.IdentityStatus=2 AND pi.UserId=m.UserId AND pi.ProviderTypeId=g.ProviderTypeId AND ((g.ProviderTypeId=1 AND pi.ProviderNamespace=g.DirectoryKey) OR (g.ProviderTypeId=2 AND pi.ProviderNamespace IN ('https://accounts.google.com','accounts.google.com'))))))))
      AND (@ScopeGroupId IS NULL OR EXISTS (SELECT 1 FROM dbo.di_group g JOIN dbo.di_userAccount u ON u.UserId=@ActorUserId WHERE g.GroupId=@ScopeGroupId AND g.GroupStatus<>4 AND (u.IsExternal=0 OR g.ProviderTypeId=3)))
    ), Chosen AS (SELECT RoleId FROM EligibleRoles WHERE Priority=(SELECT MAX(Priority) FROM EligibleRoles))
    INSERT @AccessPermissions SELECT p.PermissionCode,MAX(rp.DataScopeCode) FROM Chosen c JOIN dbo.di_rolePermission rp WITH(HOLDLOCK) ON rp.RoleId=c.RoleId AND rp.IsActive=1 JOIN dbo.di_info_permission p WITH(HOLDLOCK) ON p.PermissionId=rp.PermissionId AND p.IsActive=1 GROUP BY p.PermissionCode;

      DECLARE @LockResult int;
      DECLARE @LockName nvarchar(255)=N'DIAccessCommand:'+CONVERT(nvarchar(36),@OperationId);
      EXEC @LockResult=sys.sp_getapplock @Resource=@LockName,@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000;
      IF @LockResult<0 THROW 51009,'ACCESS_COMMAND_BUSY',1;
      IF EXISTS (SELECT 1 FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0)
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0 AND RequestHash=@RequestHash AND EventCode='commit_accessSourceRequest' AND ActorUserId=@ActorUserId) THROW 51004,'ACCESS_IDEMPOTENCY_CONFLICT',1;
        SELECT 'AlreadyApplied' Disposition,TargetKey FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0;
        COMMIT TRANSACTION; RETURN;
      END;

      IF @Command NOT IN ('REQUEST','START','COMPLETE','REJECT','CANCEL') OR @GroupId IS NULL THROW 51002,'ACCESS_SOURCE_COMMAND_INVALID',1;
      IF NOT EXISTS(SELECT 1 FROM dbo.di_group WHERE GroupId=@GroupId AND GroupStatus=2) THROW 51003,'ACCESS_GROUP_REQUIRED',1;
      DECLARE @CanManage bit=CASE WHEN EXISTS(SELECT 1 FROM @AccessPermissions WHERE PermissionCode='SOURCE.MANAGE' AND DataScopeCode=4) THEN 1 ELSE 0 END;
      IF @Command='REQUEST'
      BEGIN
        IF @RequestId IS NOT NULL OR @SourceKind NOT IN ('SHAREPOINT','GDRIVE') OR @SourceKind IS NULL OR NULLIF(LTRIM(RTRIM(@DisplayName)),N'') IS NULL
          OR @LocationUrl NOT LIKE N'https://%' OR @LocationUrl IS NULL OR @LocationUrl LIKE N'%[?#@]%' OR @LocationUrl LIKE N'%'+NCHAR(10)+N'%' OR @LocationUrl LIKE N'%'+NCHAR(13)+N'%'
          THROW 51002,'ACCESS_SOURCE_REQUEST_INVALID',1;
        IF @CanManage=0 AND NOT EXISTS(SELECT 1 FROM @AccessPermissions WHERE PermissionCode IN ('PROCESS.CREATE','PROCESS.EXECUTE','FILE.UPLOAD') AND DataScopeCode IN (2,3)) THROW 51003,'ACCESS_PERMISSION_DENIED',1;
        IF NOT EXISTS(SELECT 1 FROM dbo.di_groupScopeMapping m JOIN dbo.di_info_region r ON r.Id=m.RegionId AND r.active=1 JOIN dbo.di_info_sub_region s ON s.Id=m.SubRegionId AND s.regionId=r.Id AND s.active=1 JOIN dbo.di_info_clientnames c ON c.Id=m.ClientId AND c.active=1
          WHERE m.GroupId=@GroupId AND m.ScopeKind='REGION' AND m.IsActive=1 AND m.RegionId=@RegionId AND m.SubRegionId=@SubRegionId AND m.ClientId=@ClientId) THROW 51003,'ACCESS_SOURCE_REGION_NOT_MAPPED',1;
        DECLARE @SourceLock nvarchar(255)=N'DIAccessSource:'+CONVERT(nvarchar(36),@GroupId);
        EXEC @LockResult=sys.sp_getapplock @Resource=@SourceLock,@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000;
        IF @LockResult<0 THROW 51009,'ACCESS_COMMAND_BUSY',1;
        IF EXISTS(SELECT 1 FROM dbo.di_sourceSetupRequest WHERE GroupId=@GroupId AND SourceKind=@SourceKind AND LocationUrl=@LocationUrl AND RegionId=@RegionId AND SubRegionId=@SubRegionId AND ClientId=@ClientId AND RequestStatus IN (1,2)) THROW 51006,'ACCESS_SOURCE_REQUEST_ALREADY_PENDING',1;
        IF (SELECT COUNT(*) FROM dbo.di_sourceSetupRequest WHERE GroupId=@GroupId AND RequestedByUserId=@ActorUserId AND RequestStatus IN (1,2))>=20 THROW 51007,'ACCESS_SOURCE_REQUEST_LIMIT',1;
        INSERT dbo.di_sourceSetupRequest(GroupId,RequestedByUserId,SourceKind,DisplayName,LocationUrl,Details,RegionId,SubRegionId,ClientId)
        VALUES(@GroupId,@ActorUserId,@SourceKind,LTRIM(RTRIM(@DisplayName)),@LocationUrl,@Details,@RegionId,@SubRegionId,@ClientId);
        SET @RequestId=SCOPE_IDENTITY();
      END
      ELSE
      BEGIN
        DECLARE @Status tinyint,@Requester uniqueidentifier;
        SELECT @Status=RequestStatus,@Requester=RequestedByUserId,@SourceKind=SourceKind FROM dbo.di_sourceSetupRequest WITH(UPDLOCK,HOLDLOCK) WHERE RequestId=@RequestId AND GroupId=@GroupId AND RowVersion=@ExpectedRowVersion;
        IF @Status IS NULL OR @ExpectedRowVersion IS NULL THROW 51005,'ACCESS_CONCURRENCY_CONFLICT',1;
        IF @Command='CANCEL'
        BEGIN
          IF @Requester<>@ActorUserId OR @Status<>1 THROW 51003,'ACCESS_SOURCE_CANCELLATION_DENIED',1;
        END
        ELSE IF @CanManage=0 THROW 51003,'ACCESS_PERMISSION_DENIED',1;
        IF @Command<>'CANCEL' AND (@Status NOT IN (1,2) OR (@Command='START' AND @Status<>1)) THROW 51007,'ACCESS_SOURCE_TRANSITION_INVALID',1;
        IF @Command='REJECT' AND NULLIF(LTRIM(RTRIM(@ResolutionNote)),N'') IS NULL THROW 51002,'ACCESS_SOURCE_RESOLUTION_REQUIRED',1;
        IF @Command='COMPLETE'
        BEGIN
          IF TRY_CONVERT(uniqueidentifier,@ResourceId) IS NULL THROW 51002,'ACCESS_SOURCE_RESOURCE_REQUIRED',1;
          IF NOT EXISTS(SELECT 1 FROM dbo.di_groupScopeMapping m WHERE m.GroupId=@GroupId AND m.IsActive=1 AND m.ScopeKind=@SourceKind AND m.CanUse=1 AND m.CanManage=1 AND
            ((@SourceKind='SHAREPOINT' AND m.SharePointApplicationId=TRY_CONVERT(uniqueidentifier,@ResourceId) AND EXISTS(SELECT 1 FROM dbo.di_application a WHERE a.applicationid=m.SharePointApplicationId AND a.isactive=1 AND a.deletedon IS NULL AND ISNULL(a.isdraft,0)=0)) OR
             (@SourceKind='GDRIVE' AND m.GoogleDriveTenantId=TRY_CONVERT(uniqueidentifier,@ResourceId) AND EXISTS(SELECT 1 FROM dbo.di_gdrive_tenant t WHERE t.tenantid=m.GoogleDriveTenantId AND t.isactive=1 AND ISNULL(t.isdraft,0)=0))))
            THROW 51003,'ACCESS_SOURCE_RESOURCE_NOT_CONFIGURED_AND_MAPPED',1;
        END;
        UPDATE dbo.di_sourceSetupRequest SET RequestStatus=CASE @Command WHEN 'START' THEN 2 WHEN 'COMPLETE' THEN 3 WHEN 'REJECT' THEN 4 ELSE 5 END,
          ResourceId=CASE WHEN @Command='COMPLETE' THEN @ResourceId ELSE ResourceId END,ResolutionNote=@ResolutionNote,ResolvedByUserId=CASE WHEN @Command='CANCEL' THEN NULL ELSE @ActorUserId END,UpdatedAtUTC=@Now WHERE RequestId=@RequestId;
      END;
      SELECT RequestId,GroupId,RequestStatus,ResourceId,RowVersion FROM dbo.di_sourceSetupRequest WHERE RequestId=@RequestId;

      INSERT dbo.di_accessAudit(OperationId,RequestHash,ActorUserId,ActorServiceCode,GroupId,EventCode,TargetType,TargetKey,Outcome,ChangeSummary,CorrelationId)
      VALUES(@OperationId,@RequestHash,@ActorUserId,NULL,@GroupId,'commit_accessSourceRequest','ACCESS',COALESCE(CONVERT(nvarchar(200),@RequestId),N''),1,N'Command='+@Command,@CorrelationId);
      COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
      IF XACT_STATE()<>0 ROLLBACK TRANSACTION;
      THROW;
    END CATCH;
END;
GO

SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

CREATE PROCEDURE dbo.commit_accessProcessAction
    @ActorUserId uniqueidentifier,
    @ActorSessionId uniqueidentifier,
    @SessionHash binary(32),
    @OperationId uniqueidentifier,
    @RequestHash binary(32),
    @CorrelationId uniqueidentifier,
    @ExpectedRowVersion binary(8)=NULL,
    @Command varchar(12),
    @GroupId uniqueidentifier,
    @ProcessId bigint,
    @ExpectedStateVersion binary(32),
    @ProcessName nvarchar(100)=NULL,
    @Description nvarchar(4000)=NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @Now datetime2(3)=SYSUTCDATETIME();
    IF @OperationId IS NULL OR @RequestHash IS NULL OR @CorrelationId IS NULL THROW 51002,'ACCESS_COMMAND_METADATA_REQUIRED',1;
    BEGIN TRY
      BEGIN TRANSACTION;
    IF NOT EXISTS (SELECT 1 FROM dbo.di_userSession s WITH(HOLDLOCK) JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=s.UserId JOIN dbo.di_userIdentity i WITH(HOLDLOCK) ON i.IdentityId=s.IdentityId AND i.UserId=s.UserId WHERE s.SessionId=@ActorSessionId AND s.SessionHash=@SessionHash AND s.UserId=@ActorUserId AND s.RevokedAtUTC IS NULL AND s.AbsoluteExpiresAtUTC>@Now AND s.IdleExpiresAtUTC>@Now AND s.UserSecurityVersion=u.SecurityVersion AND u.AccountStatus=2 AND i.IdentityStatus=2) THROW 51001,'ACCESS_SESSION_INVALID',1;
    DECLARE @ScopeGroupId uniqueidentifier=@GroupId;
    DECLARE @AccessPermissions TABLE(PermissionCode varchar(100) PRIMARY KEY,DataScopeCode tinyint NOT NULL);
    ;WITH EligibleRoles AS (
      SELECT ur.RoleId,r.Priority FROM dbo.di_userRoleMapping ur WITH(HOLDLOCK) JOIN dbo.di_role r WITH(HOLDLOCK) ON r.RoleId=ur.RoleId AND r.IsActive=1
      WHERE ur.UserId=@ActorUserId AND ur.IsActive=1 AND ur.BeginsAtUTC<=@Now AND (ur.EndsAtUTC IS NULL OR ur.EndsAtUTC>@Now)
      AND ((ur.GrantScope='A' AND ur.RoleId IN (4,5)) OR (ur.GrantScope='G' AND ur.GroupId=@ScopeGroupId AND EXISTS (
        SELECT 1 FROM dbo.di_groupMembership m WITH(HOLDLOCK) JOIN dbo.di_group g WITH(HOLDLOCK) ON g.GroupId=m.GroupId JOIN dbo.di_userAccount u WITH(HOLDLOCK) ON u.UserId=m.UserId LEFT JOIN dbo.di_userIdentity pi WITH(HOLDLOCK) ON pi.IdentityId=m.ProofIdentityId
        JOIN dbo.di_groupRoleMapping gr WITH(HOLDLOCK) ON gr.GroupId=m.GroupId AND gr.RoleId=ur.RoleId AND gr.IsActive=1
        WHERE m.MembershipId=ur.MembershipId AND m.UserId=ur.UserId AND ur.GrantMembershipEpoch=m.MembershipEpoch AND m.LocalState=1 AND m.ApprovalStatus IN (0,2,4) AND g.GroupStatus=2 AND (u.IsExternal=0 OR g.ProviderTypeId=3) AND (g.ProviderTypeId=3 OR (m.ProofStatus=1 AND m.ProofExpiresAtUTC>@Now AND m.ProofObservedAtUTC>=DATEADD(minute,-15,@Now) AND pi.IdentityStatus=2 AND pi.UserId=m.UserId AND pi.ProviderTypeId=g.ProviderTypeId AND ((g.ProviderTypeId=1 AND pi.ProviderNamespace=g.DirectoryKey) OR (g.ProviderTypeId=2 AND pi.ProviderNamespace IN ('https://accounts.google.com','accounts.google.com'))))))))
      AND (@ScopeGroupId IS NULL OR EXISTS (SELECT 1 FROM dbo.di_group g JOIN dbo.di_userAccount u ON u.UserId=@ActorUserId WHERE g.GroupId=@ScopeGroupId AND g.GroupStatus<>4 AND (u.IsExternal=0 OR g.ProviderTypeId=3)))
    ), Chosen AS (SELECT RoleId FROM EligibleRoles WHERE Priority=(SELECT MAX(Priority) FROM EligibleRoles))
    INSERT @AccessPermissions SELECT p.PermissionCode,MAX(rp.DataScopeCode) FROM Chosen c JOIN dbo.di_rolePermission rp WITH(HOLDLOCK) ON rp.RoleId=c.RoleId AND rp.IsActive=1 JOIN dbo.di_info_permission p WITH(HOLDLOCK) ON p.PermissionId=rp.PermissionId AND p.IsActive=1 GROUP BY p.PermissionCode;

      DECLARE @LockResult int;
      DECLARE @LockName nvarchar(255)=N'DIAccessCommand:'+CONVERT(nvarchar(36),@OperationId);
      EXEC @LockResult=sys.sp_getapplock @Resource=@LockName,@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000;
      IF @LockResult<0 THROW 51009,'ACCESS_COMMAND_BUSY',1;
      IF EXISTS (SELECT 1 FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0)
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0 AND RequestHash=@RequestHash AND EventCode='commit_accessProcessAction' AND ActorUserId=@ActorUserId) THROW 51004,'ACCESS_IDEMPOTENCY_CONFLICT',1;
        SELECT 'AlreadyApplied' Disposition,TargetKey FROM dbo.di_accessAudit WHERE OperationId=@OperationId AND EventSequence=0;
        COMMIT TRANSACTION; RETURN;
      END;

      IF @Command NOT IN ('EDIT','DISABLE','ENABLE','DELETE','REMOVE') OR @GroupId IS NULL OR @ProcessId IS NULL OR @ExpectedStateVersion IS NULL THROW 51002,'ACCESS_PROCESS_COMMAND_INVALID',1;
      DECLARE @Permission varchar(100)=CASE WHEN @Command='EDIT' THEN 'PROCESS.EDIT' WHEN @Command IN ('DELETE','REMOVE') THEN 'PROCESS.DELETE' ELSE 'PROCESS.DISABLE' END;
      DECLARE @ViewMode char(1)='G';

    -- #region Read-only business access: scope before projection, paging and aggregation
    DECLARE @DataScope tinyint=(SELECT DataScopeCode FROM @AccessPermissions WHERE PermissionCode=@Permission);
    IF @ViewMode IS NULL OR @ViewMode NOT IN ('G','A') OR (@ViewMode='G' AND @GroupId IS NULL) OR (@ViewMode='A' AND @GroupId IS NOT NULL) THROW 51002,'ACCESS_BUSINESS_VIEW_INVALID',1;
    IF (@ViewMode='A' AND ISNULL(@DataScope,0)<3) OR ISNULL(@DataScope,0) NOT BETWEEN 1 AND 3 THROW 51003,'ACCESS_BUSINESS_SCOPE_DENIED',1;
    CREATE TABLE #EligibleGroups(GroupId uniqueidentifier NOT NULL PRIMARY KEY,LegacySecurityGroupId varchar(200) NOT NULL);
    INSERT #EligibleGroups(GroupId,LegacySecurityGroupId)
      SELECT g.GroupId,g.LegacySecurityGroupId FROM dbo.di_group g WITH(HOLDLOCK)
      JOIN dbo.di_info_securityGroup oldg WITH(HOLDLOCK) ON oldg.id=g.LegacySecurityGroupRowId AND oldg.securityGroupId COLLATE Latin1_General_100_BIN2=g.LegacySecurityGroupId COLLATE Latin1_General_100_BIN2
      WHERE g.GroupStatus=2 AND oldg.active=1 AND (@ViewMode='A' OR g.GroupId=@GroupId)
        AND (g.ProviderTypeId=3 OR NOT EXISTS(SELECT 1 FROM dbo.di_userAccount WHERE UserId=@ActorUserId AND IsExternal=1));
    -- #endregion

      IF @DataScope NOT IN (2,3) THROW 51003,'ACCESS_PERMISSION_DENIED',1;
      DECLARE @ConfigurationId nvarchar(100),@CurrentState binary(32);
      SELECT @ConfigurationId=p.flpConfigurationId,@CurrentState=HASHBYTES('SHA2_256',CONVERT(varbinary(max),(SELECT p.process_name,p.Description,p.is_active,p.modified_date,p.regionId,p.subRegionId,p.clientId,p.sharePointApplicationId,p.sourcePath,p.destinationPath FOR JSON PATH,WITHOUT_ARRAY_WRAPPER,INCLUDE_NULL_VALUES))) FROM dbo.di_flpConfiguration p WITH(UPDLOCK,HOLDLOCK)
        WHERE p.id=@ProcessId AND p.is_active IN (0,1) AND NOT EXISTS(SELECT 1 FROM dbo.di_flpConfiguration ambiguous WITH(HOLDLOCK) WHERE ambiguous.flpConfigurationId=p.flpConfigurationId AND ambiguous.id<>p.id) AND EXISTS(
        SELECT 1 FROM #EligibleGroups eg
        JOIN dbo.di_flpConfigurationSecurityGroupMapping oldm WITH(HOLDLOCK) ON oldm.securityGroupId=eg.LegacySecurityGroupId AND oldm.flpConfigurationId=p.flpConfigurationId AND oldm.active=1
        JOIN dbo.di_groupScopeMapping sm WITH(HOLDLOCK) ON sm.GroupId=eg.GroupId AND sm.ScopeKind='REGION' AND sm.IsActive=1 AND sm.RegionId=p.regionId AND sm.ClientId=p.clientId AND CONVERT(varchar(55),sm.SubRegionId)=p.subRegionId
        JOIN dbo.di_info_region r WITH(HOLDLOCK) ON r.Id=sm.RegionId AND r.active=1
        JOIN dbo.di_info_sub_region sr WITH(HOLDLOCK) ON sr.Id=sm.SubRegionId AND sr.regionId=r.Id AND sr.active=1
        JOIN dbo.di_info_clientnames c WITH(HOLDLOCK) ON c.Id=sm.ClientId AND c.active=1);
      IF @ConfigurationId IS NULL THROW 51003,'ACCESS_PROCESS_SCOPE_DENIED',1;
      IF @CurrentState<>@ExpectedStateVersion THROW 51005,'ACCESS_CONCURRENCY_CONFLICT',1;
      DECLARE @LegacyGroup varchar(200)=(SELECT LegacySecurityGroupId FROM #EligibleGroups WHERE GroupId=@GroupId);
      IF @Command='REMOVE'
      BEGIN
        -- Remove only this group's association. Other groups, files and schedules are retained.
        UPDATE dbo.di_flpConfigurationSecurityGroupMapping SET active=0,updationDateTime=@Now WHERE flpConfigurationId=@ConfigurationId AND securityGroupId=@LegacyGroup AND active=1;
        IF @@ROWCOUNT=0 THROW 51005,'ACCESS_CONCURRENCY_CONFLICT',1;
      END
      ELSE
      BEGIN
        -- Global configuration metadata affects every association, so shared rows require review.
        IF EXISTS(SELECT 1 FROM dbo.di_flpConfigurationSecurityGroupMapping WITH(HOLDLOCK) WHERE flpConfigurationId=@ConfigurationId AND active=1 AND securityGroupId<>@LegacyGroup)
          THROW 51040,'ACCESS_SHARED_PROCESS_REQUIRES_REVIEW',1;
        IF @Command='EDIT' AND (NULLIF(LTRIM(RTRIM(@ProcessName)),N'') IS NULL OR CONVERT(nvarchar(100),CONVERT(varchar(100),@ProcessName)) COLLATE Latin1_General_100_BIN2<>@ProcessName COLLATE Latin1_General_100_BIN2
          OR (@Description IS NOT NULL AND CONVERT(nvarchar(4000),CONVERT(varchar(4000),@Description)) COLLATE Latin1_General_100_BIN2<>@Description COLLATE Latin1_General_100_BIN2))
          THROW 51002,'ACCESS_LEGACY_TEXT_ENCODING_UNSUPPORTED',1;
        UPDATE dbo.di_flpConfiguration SET process_name=CASE WHEN @Command='EDIT' THEN @ProcessName ELSE process_name END,
          Description=CASE WHEN @Command='EDIT' THEN @Description ELSE Description END,
          is_active=CASE @Command WHEN 'DELETE' THEN 0 WHEN 'DISABLE' THEN 0 WHEN 'ENABLE' THEN 1 ELSE is_active END,modified_date=@Now,
          updatedBy=CONVERT(varchar(36),@ActorUserId),updatedByName=(SELECT LEFT(DisplayName,150) FROM dbo.di_userAccount WHERE UserId=@ActorUserId)
          WHERE id=@ProcessId;
        -- Logical deletion retains configuration, mappings/history, files and schedules for recovery.
        -- A shared configuration is rejected above before either table can be changed.
        IF @Command='DELETE'
          UPDATE dbo.di_flpConfigurationSecurityGroupMapping SET active=0,updationDateTime=@Now WHERE flpConfigurationId=@ConfigurationId AND securityGroupId=@LegacyGroup AND active=1;
      END;
      SELECT CONVERT(nvarchar(100),@ProcessId) AS ProcessId,@Command AS AppliedCommand;

      INSERT dbo.di_accessAudit(OperationId,RequestHash,ActorUserId,ActorServiceCode,GroupId,EventCode,TargetType,TargetKey,Outcome,ChangeSummary,CorrelationId)
      VALUES(@OperationId,@RequestHash,@ActorUserId,NULL,@GroupId,'commit_accessProcessAction','ACCESS',COALESCE(CONVERT(nvarchar(200),@ProcessId),N''),1,N'Command='+@Command,@CorrelationId);
      COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
      IF XACT_STATE()<>0 ROLLBACK TRANSACTION;
      THROW;
    END CATCH;
END;
GO

GRANT EXECUTE ON OBJECT::dbo.sel_accessApplicationView TO access_api_executor;
GRANT EXECUTE ON OBJECT::dbo.sel_accessHierarchy TO access_api_executor;
GRANT EXECUTE ON OBJECT::dbo.sel_accessSources TO access_api_executor;
GRANT EXECUTE ON OBJECT::dbo.commit_accessSourceRequest TO access_api_executor;
GRANT EXECUTE ON OBJECT::dbo.commit_accessProcessAction TO access_api_executor;

GO
