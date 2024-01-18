We have always seen database level access to the end user but this following walk through will help you to understand 
how to setup Row level security access for Table in Azure Database
This entire SQL scripts developed and tested by meself. There are fours parts and follow the Step to achive the goal.

--********************************************************** 
  --PART 1 Database level User Access RLS AD
  -- End User Added on below 3 AD Groups
  
--**********************************************************
--Group Name: AZ-AS-GRP1 
--Group Name: AZ-AS-GRP2
--Group Name: AZ-AS-GRP3

  -- STEP 1
CREATE USER [AZ-AS-GRP1] FROM  EXTERNAL PROVIDER  WITH DEFAULT_SCHEMA=[dbo]
GO
CREATE USER [AZ-AS-GRP2] FROM  EXTERNAL PROVIDER  WITH DEFAULT_SCHEMA=[dbo]
GO
CREATE USER [AZ-AS-GRP3] FROM  EXTERNAL PROVIDER  WITH DEFAULT_SCHEMA=[dbo]
GO

-- STEP 2 Database Role
CREATE ROLE db_RLS_DataReader   AUTHORIZATION [dbo]
GO

--STEP 3 Grant select permission to Database Role
 GRANT SELECT ON OBJECT::RPT.DIM_PRODUCT_SALES TO [db_RLS_DataReader] 

  -- STEP 4 Add an existing user to the role
ALTER ROLE [db_RLS_DataReader] add member  [AZ-AS-GRP1] 
ALTER ROLE [db_RLS_DataReader] add member  [AZ-AS-GRP2]
ALTER ROLE [db_RLS_DataReader] add member  [AZ-AS-GRP3] 

--==========================================================================
 -- Validate the Role

SELECT  
    members.name as 'members_name', 
    roles.name as 'roles_name',
    roles.type_desc as 'roles_desc' ,
    members.type_desc as 'members_desc'
FROM sys.database_role_members rolemem INNER JOIN sys.database_principals roles
ON rolemem.role_principal_id = roles.principal_id
INNER JOIN sys.database_principals members ON rolemem.member_principal_id = members.principal_id
WHERE roles.name ='db_RLS_DataReader'

 --==================================================================================

 --********************************************************** 
 --PART 2 Row Level User Access Table
 --  STEP 5   RLS User Access table
 --********************************************************** 

CREATE TABLE [RPT].[DIM_DATA_USER_ACCESS](
[ID]				 [int]  IDENTITY(1,1) NOT NULL ,
[Assign_Nm]		 [varchar](20) NULL,
[AAD_Group_Name]     [nvarchar] (120) NULL,
[User_Email_Id]  [varchar] (60) NULL,
[Is_Active]			 [bit]  default(1) NULL,
[Deletion_DT]		 [datetime] NULL, -- 1 Active , 0 InActive
[Created_By]    [varchar](50)  DEFAULT  suser_sname() NULL,
[Created_Date]  [datetime] DEFAULT  getdate()  NULL,
[Modified_By]   [varchar](50)  DEFAULT  suser_sname() NULL,
[Modified_Date] [datetime] DEFAULT  getdate()  NULL,
 CONSTRAINT [PK_ID2] PRIMARY KEY CLUSTERED 
 (
 [ID] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO 

 -- STEP 6: Create the specified users
CREATE USER FULL_DATA WITHOUT LOGIN;
GO
CREATE USER SALES_DATA1 WITHOUT LOGIN;
GO
CREATE USER IT_DATA2 WITHOUT LOGIN;
GO
CREATE USER PRO_DATA3 WITHOUT LOGIN;
GO


 -- INSERT  DATA

SELECT * FROM [RPT].[DIM_DATA_USER_ACCESS]  where User_Email_Id =user_name()
 INSERT INTO [RPT].[DIM_DATA_USER_ACCESS]  (  [ID], [Assign_Nm], [AAD_Group_Name]  , [User_Email_Id])
 VALUES (1,	'SALES_DATA1' , 'AAD1',  'MyUser1@abc.com'  )
 INSERT INTO [RPT].[DIM_DATA_USER_ACCESS]  (  [ID], [Assign_Nm], [AAD_Group_Name]  , [User_Email_Id])
 VALUES (2,	'IT_DATA2',  'AAD2',  'MyUser2@abc.com'     )
 INSERT INTO [RPT].[DIM_DATA_USER_ACCESS]  (  [ID], [Assign_Nm], [AAD_Group_Name]  , [User_Email_Id])
 VALUES (3,	'PRO_DATA3', 'AAD3',  'MyUser3@abc.com' ) 



-- STEP 7

GRANT SELECT ON [RPT].[DIM_DATA_USER_ACCESS]  TO FULL_DATA;
GRANT UPDATE ON [RPT].[DIM_DATA_USER_ACCESS]  TO FULL_DATA;
GRANT DELETE ON [RPT].[DIM_DATA_USER_ACCESS]  TO FULL_DATA;
GRANT INSERT ON [RPT].[DIM_DATA_USER_ACCESS]  TO FULL_DATA;

GRANT SELECT ON [RPT].[DIM_DATA_USER_ACCESS]  TO [AZ-AS-GRP1]
GRANT SELECT ON [RPT].[DIM_DATA_USER_ACCESS]  TO [AZ-AS-GRP2]
GRANT SELECT ON [RPT].[DIM_DATA_USER_ACCESS]  TO [AZ-AS-GRP3]

 --==================================================================================
 --********************************************************** 
 --PART 3 Security and Functions
 --********************************************************** 
 -- STEP 8: Create the inline table-valued function
 -- DROP FUNCTION [dbo].[fn_MY_Security]
 --GO 



CREATE FUNCTION  dbo.fn_MY_Security
(@MAPPING_NAME NVARCHAR (255) ) --, @USER_NAME NVARCHAR (255)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN 

SELECT 1 AS fn_MY_Security_Result
WHERE @MAPPING_NAME IN 
( SELECT DISTINCT DH.[Assign_Nm]
   FROM [RPT].[DIM_MY_DEPT] AS DH
   INNER JOIN [RPT].[DIM_DATA_USER_ACCESS] AS UA
   ON DH.[Assign_Nm] = UA.[Assign_Nm] 
    WHERE (LOWER( [User_Email_Id])  = LOWER( USER_NAME() ) -- Specific User
	 AND [Is_Active]=1) OR LOWER( USER_NAME() ) = 'FULL_DATA' -- Admin User
)	           
GO

 -- STEP 9: Apply the Security Policy
 -- DROP SECURITY POLICY [dbo].[MY_UserFilter]
 -- GO

CREATE SECURITY POLICY [dbo].[MY_UserFilter]
ADD FILTER PREDICATE   [dbo].fn_MY_Security([Assign_Nm])   
ON [RPT].[DIM_DATA_USER_ACCESS]  
WITH (STATE = ON);

GO

  ---==============================================================================
  --********************************************************** 
 --PART 4   
  -- -- STEP 10 Data Validateion
  --********************************************************** 
-- All data for Admin RLS

EXECUTE AS USER = 'FULL_DATA';
SELECT * FROM  [RPT].[DIM_DATA_USER_ACCESS]
  WHERE AAD_Group_Name LIKE 'AZ%'    
REVERT;

GO
EXECUTE AS USER = 'FULL_DATA';
SELECT * FROM  [RPT].[DIM_DATA_USER_ACCESS]
  WHERE AAD_Group_Name LIKE 'AZ%'     
  ORDER BY 2 
REVERT;
GO

--Specific users

EXECUTE AS USER = 'SALES_DATA1';
SELECT * FROM  [RPT].[DIM_DATA_USER_ACCESS]
REVERT;
GO

EXECUTE AS USER = 'IT_DATA2';
SELECT * FROM  [RPT].[DIM_DATA_USER_ACCESS]
REVERT;
GO

EXECUTE AS USER = 'PRO_DATA3';
SELECT * FROM  [RPT].[DIM_DATA_USER_ACCESS]
REVERT;
GO

 --This catalog view returns all the Security Policies in the database
 --Execute the following statement to get all the security policies in the database with important security policy attributes/columns


SELECT Name, object_id, type, type_desc,is_ms_shipped,is_enabled,is_schema_bound
FROM sys.security_policies
 

--This catalog view returns all the Security Predicates in the database
SELECT * 
FROM sys.security_predicates





 

