-- +----------------------------------------------------------------------------------------+
-- |  -- Script Name: create_database_user_pwd_pgcm.sql                                     |
-- |  -- Description : to create user_pgcm DB user that will be used to support                |
-- |                   the following *authentication types AWS* *Secrets* ** *Manager* ** *and* ** *|*
-- | *clear password* *(**username**/**passsword**)* ** *.* *|* 
-- |  -- Change History :                                                                   |
-- +----------------------------------------------------------------------------------------+
\echo 'pg db name: ':DBNAME
\echo 'pg endpoint: ':HOST
\prompt 'Please provide the user_pgcm User password  :' user_pgcm_pwd
create user sm_pgcm with login ENCRYPTED PASSWORD :'user_pgcm_pwd';
grant connect on database :DBNAME to user_pgcm;
alter user user_pgcm connection limit 2;
grant pg_monitor to user_pgcm;
\du user_pgcm
