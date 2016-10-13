USE [master]
GO

/****** Object:  StoredProcedure [dbo].[EncryptionObjectBackup]    Script Date: 10/13/2016 6:56:20 AM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO




/*********************************************************************************************
Create By:	Clint Spann


Revision History:
-- 8/5/2016 – Created.  Yay!!!
  
  
Purpose:	This procedure generates a script which can be manually run to back up all certs and keys to the 
			directory of your choosing with a password of your choosing		

     
Disclaimer: Use this procedure at your own risk.   I take no responsibility for the outcome of this procedure 
			on your system(s).  Please read, and be aware of, the "NEEDED TESTING" and "KNOWN ISSUES/CAVEATS" below - 
			these sections descibe potential issues with the code that may, or may not, affect your use of it.


NEEDED TESTING:
--Haven't actually tested the subsequent functionality of the restored objects we are backing up


KNOWN ISSUES/CAVEATS:
--does not back up any of the MS shipped objects except for Service Master Keys and Database Master Keys
--all keys/certs of the same type have to have the same password
--there is a Pass column in the output that is unused
--if a password is needed to decrypt a key when backing it up, it is not currently handled


Parameters:

@pSMKPass
	Password for the Service Master Key

@pSMKPath
	Backup path for the Service Master Key

@pDMKPass 
	Password for the Database Master Key

@pDMKPath
	Backup path for the Database Master Key

@pCertPass
	Password for Certificates

@pCertPath
	Path for Certificates

@pPrivateKeyPath
	Path for Private Key of Certificates

-----------------------------------------------
TEST BLOCK

exec [dbo].[EncryptionObjectBackup]
 @pSMKPass = ''
,@pSMKPath = 'A:\Backups\'
,@pDMKPass = ''
,@pDMKPath = 'A:\Backups\'
,@pCertPass = ''
,@pCertPath = 'A:\Backups\'
,@pPrivateKeyPath = 'A:\Backups\'

-----------------------------------------------
*********************************************************************************************/


ALTER PROCEDURE [dbo].[EncryptionObjectBackup]
(
 @pSMKPass VARCHAR(20)
,@pSMKPath VARCHAR(100)
,@pDMKPass VARCHAR(20)
,@pDMKPath VARCHAR(100)
,@pCertPass VARCHAR(20)
,@pCertPath VARCHAR(100)
,@pPrivateKeyPath VARCHAR(100)
)
AS 


SET NOCOUNT ON;



--Declare variables


DECLARE @RunCommand VARCHAR(1000);
DECLARE @Counter INT = 0;
DECLARE @RowCount INT;
DECLARE @RowToDelete INT;



--Create Tables

CREATE TABLE #DatabaseList
( ID INT IDENTITY (1,1)
, DatabaseName VARCHAR(255)
, Command VARCHAR(1000)
);   

CREATE TABLE #Commands
(
 RunPriority INT IDENTITY (1,1)
,ObjectName VARCHAR(100)
,DatabaseName VARCHAR(255)
,ObjectType VARCHAR(10)
,CryptTypeDesc VARCHAR(50)
,Pass VARCHAR(20)
,Command VARCHAR (1000)
);



--Get all online databases
INSERT INTO #DatabaseList (DatabaseName)
select name
from sys.databases
WHERE state = 0		--is ONLINE
ORDER BY name;


--Initialize row count
SET @RowCount = 
(
SELECT COUNT(*)
FROM #DatabaseList
);

--Create dynamic statement to populate the temp table for each database on the instance
WHILE @Counter < @RowCount
BEGIN

SET @RunCommand = 
(
SELECT 'USE ' + DatabaseName + ' INSERT INTO #Commands(ObjectName, DatabaseName, ObjectType, CryptTypeDesc) SELECT NAME, DB_NAME(), ''symKey'', crypt_type_desc FROM sys.symmetric_keys sk INNER JOIN sys.key_encryptions ke ON sk.symmetric_key_id = ke.key_id INSERT INTO #Commands(ObjectName, DatabaseName, ObjectType, CryptTypeDesc) SELECT NAME, DB_NAME(), ''cert'', pvt_key_encryption_type_desc FROM sys.certificates'
FROM #DatabaseList
WHERE ID = (@Counter +1)
);

EXEC(@RunCommand);

SET @Counter = @Counter + 1;

END;



--remove unneeded MS objects and symmetric keys that can't be backed up

DELETE FROM #Commands
WHERE ObjectName LIKE '%MS_AgentSigningCertificate%'
OR ObjectName LIKE '%MS_PolicySigningCertificate%'
OR ObjectName LIKE '%MS_SchemaSigningCertificate%'
OR ObjectName LIKE '%MS_SmoExtendedSigningCertificate%'
OR ObjectName LIKE '%MS_SQLAuthenticatorCertificate%'
OR ObjectName LIKE '%MS_SQLReplicationSigningCertificate%'
OR ObjectName LIKE '%MS_SQLResourceSigningCertificate%'
OR (ObjectName NOT IN ('##MS_ServiceMasterKey##','##MS_DatabaseMasterKey##') AND ObjectType = 'symKey');


--remove any objects that are encrypted by password if they are also encrypted by master key (so we don't try to use the password to decrypt later)

DELETE c2
FROM #Commands c1
INNER JOIN #Commands c2 on c1.ObjectName = c2.ObjectName 
and c1.DatabaseName = c2.DatabaseName 
and c1.ObjectType = c2.ObjectType 
and c1.CryptTypeDesc <> c2.CryptTypeDesc
where c1.CryptTypeDesc = 'ENCRYPTION BY MASTER KEY'
and c2.CryptTypeDesc = 'ENCRYPTION BY PASSWORD';


--Get the row ID of any unneeded row, then delete the row

SELECT @RowToDelete = MIN(c1.RunPriority)
FROM #Commands c1
INNER JOIN #Commands c2 on c1.ObjectName = c2.ObjectName AND c1.DatabaseName = c2.DatabaseName AND c1.ObjectType = c2.ObjectType AND c1.CryptTypeDesc = c2.CryptTypeDesc AND c1.RunPriority <> c2.RunPriority
WHERE c1.ObjectName = '##MS_ServiceMasterKey##'
and c1.CryptTypeDesc = 'ENCRYPTION BY MASTER KEY';

DELETE FROM #Commands 
WHERE RunPriority = @RowToDelete




--Update the commands to contain the proper backup syntax for the object

UPDATE #Commands 
SET Command = 
CASE
	WHEN ObjectType = 'symKey' AND  ObjectName = '##MS_ServiceMasterKey##'
		THEN 'USE ' + DatabaseName + ' BACKUP SERVICE MASTER KEY TO FILE = ''' + @pSMKPath + '_' + DatabaseName + '_' + ObjectName + '_' + CONVERT(VARCHAR(10), GETDATE(), 112) + ''' ENCRYPTION BY PASSWORD = ''' + @pSMKPass + ''''
	WHEN ObjectType = 'symKey' AND ObjectName = '##MS_DatabaseMasterKey##'
		THEN 'USE ' + DatabaseName + ' BACKUP MASTER KEY TO FILE = ''' + @pDMKPath + '_' + DatabaseName + '_' + ObjectName + '_' + CONVERT(VARCHAR(10), GETDATE(), 112) + ''' ENCRYPTION BY PASSWORD = ''' + @pDMKPass + ''''
	WHEN ObjectType = 'cert'
		THEN 'USE ' + DatabaseName + ' BACKUP CERTIFICATE ' + ObjectName + ' TO FILE = ''' + @pCertPath + '_' + DatabaseName + '_' + ObjectName + '_' + CONVERT(VARCHAR(10), GETDATE(), 112) + ''' WITH PRIVATE KEY (FILE = ''' + @pPrivateKeyPath + '_' + DatabaseName + '_PK' + ObjectName + '_' + CONVERT(VARCHAR(10), GETDATE(), 112) + ''', ENCRYPTION BY PASSWORD = ''' + @pCertPass + ''')'
END	
FROM #Commands;



--Return list to copy and execute

SELECT * 
FROM #Commands;



--Drop tables

IF OBJECT_ID('tempdb..#DatabaseList') IS NOT NULL  
DROP TABLE #DatabaseList;

IF OBJECT_ID('tempdb..#Commands') IS NOT NULL  
DROP TABLE #Commands;


GO


