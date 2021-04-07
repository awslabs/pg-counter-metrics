-- +----------------------------------------------------------------------------------------+
-- |  -- Script Name: create_database_user_iam_pgcm.sql                                     |
-- |  -- Description : to create user_pgcm DB user that will use IAM Database Authentication|
-- |  -- Change History :                                                                   |
-- +----------------------------------------------------------------------------------------+
\echo 'pg db name: ':DBNAME
\echo 'pg endpoint: ':HOST
create user user_pgcm with login;
grant rds_iam to user_pgcm;
grant connect on database :DBNAME to user_pgcm;
alter user user_pgcm connection limit 2;
grant pg_monitor to user_pgcm;
\du user_pgcm
