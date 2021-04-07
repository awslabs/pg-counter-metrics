# PG Counter Metrics (PGCM)

<image src = "img/pgcm.png"></image>

## What is PG Counter Metrics (PGCM) ?
PG Counter Metrics ( PGCM ) is a tool for publishing PostgreSQL performance data to CloudWatch. By publishing to CloudWatch, dashboards and alarming can be used on the collected data.

Pg Counter Metrics ( PGCM ) components  :

    - Lambda
    - CloudWatch dashboard
    - CloudWatch metrics
    - CloudWatch alarms
    - RDS IAM database authentication
    - AWS Secrets Manager
    - python

**Note**: PG Counter Metrics support only one database in the PostgreSQL instance , in the future release it will suppport more than one Database and it will provide database performance metrics per database .

## Why do we need PG Counter Metrics (PGCM) ?
- PostgreSQL has no any historical performance data
- PG Counter Metrics’s CloudWatch metrics will be used with CloudWatch alarms to be the advanced alarm system 
- PGCM provide comprehensive dashbaord and metrics 



## Supported authentication types :
PGCM support three authentication types

    1- IAM Database Authentication
    2- AWS Secrets Manager
    3- clear password ( it should be used for TEST ENV and debuing mode only )

<image src = "img/authentication_types.png"></image>

## PG Counter Metrics Types :
There are three type of metrics

    1- Database performance metrics
    2- Table metrics (per table)
    3- pg_stat_statements (only for the top 20 query that consume the DB time / per query id)

### 1- Database performance  metrics :
|   #   | Counter Metric Name       | Description     |
| :---: | :-------------------------| :------------- | 
|1|Xid_Percent_Towards_Wraparound| Percent Towards Wraparound      |
|2|percent_towards_emergency_autovacuum|  Percent towards emergency autovacuum, when XID reach autovacuum_freeze_max_age parameter value     |  
|3|queries_canceled_due_to_lock_timeouts|   number of queries canceled due to lock timeouts              |               
|4|queries_canceled_due_to_lock_deadlocks|   number of queries canceled due to  dead locks              |
|5|idle_in_transaction_sessions|  number of idle in transaction sessions               |  
|6|idle_sessions|number of idle sessions|  
|7|idle_in_transaction_aborted_sessions|number of idle in transaction aborted sessions|  
|8|active_sessions|number of active sessions|  
|9|Inactive_replication_slots|number of Inactive replication slots|  
|10|Active_replication_slots|number of Active replication slots| 
|11|invalid_indexes|number of invalid indexes| 
|12|deadlocks|number of deadlocks|
|13|total_connections|total number of connection |
|14|max_connections|max_connections parameter value|
|15|autovacuum_freeze_max_age|autovacuum_freeze_max_age parameter value|
|16|oldest_xid|oldest Transaction ID|
|17|autovacuum_count_per_min|how many autovacuum excuted per min|
|18|autovacuum_count_per_hour|how many autovacuum excuted per hour|
|19|autovacuum_count_per_day|how many autovacuum excuted per day|
|20|autoanalyze_count_per_min|how many autoanalyze excuted per min|
|21|autoanalyze_count_per_hour|how many autoanalyze excuted per hour|
|22|autoanalyze_count_per_day|how many autoanalyze excuted per day|
|23|total_DB_size_in_GB|total databases size in the Postgresql instance|
|24|blocked_sessions|number of blocked sessions|
|25|wait_event| wait_event / session count, how many sessions waiting on each wait event ,this metric is dynamic and it will create new cloud watch metric every time there is new wait event appear in the DB|
|26|oldest_open_transaction|this metic will show the longest running transaction for the active sessions only  |
|27|oldest_open_idl_in_transaction|this metic will show the longest running idl in transaction for the sessions with idl in transaction status|
|28|n_tables_eligible_for_autovacuum|number of  tables eligible for autovacuum|
|29|not_granted_lock|number of  not granted lock|
|30|lock_mode|lock_mode column in pg_locks / session count,how many sessions waiting on each lock mode |
|31|lock_type|lock_type column in pg_locks / session count,how many sessions waiting on each lock_type |
|32|xact_commit|number of commits|
|33|xact_rollback|number of rollback|
|34|xact_commit_ratio|commit ratio|
|35|tup_returned|Number of rows returned by all queries|
|36|tup_fetched|Number of rows fetched by all queries|
|37|tup_updated|Number of rows updated by all queries|
|38|tup_deleted|Number of rows deleted by all queries|
|39|tup_inserted|Number of rows inserted by all queries|
|40|checkpoints_requested|Number of requested checkpoints that have been performed|
|41|checkpoints_timed|Number of scheduled checkpoints that have been performed|
|42|connections_utilization|100*( total_connections / max_connections)|
|43|Oldest_Replication_Slot_Lag_gb_behind|The lagging size of the Oldest Replication Slot|
|44|Oldest_Replication_Slot_Lag_gb_behind_per_slot_(slot_name)|The lagging size for each Replication Slot|
|45|DBLoadCPU|total number of active sessions waiting on CPU|
|46|DBLoadNoneCPU|total number of active sessions waiting on None CPU wait event|
|47|bgwriter_buffers_backend|Number of buffers written directly by a backend|
|48|bgwriter_maxwritten_clean|Number of times the background writer stopped a cleaning scan because it had written too many buffers|
|49|bgwriter_buffers_clean|Number of buffers written by the background writer|
|50|oldest_mxid|the oldest Multixact IDs (MXID)|
|51|autovacuum_multixact_freeze_max_age| autovacuum_multixact_freeze_max_age parameter value |



![](img/pgcm.gif)

### 2- Table metrics (per Table):

Table Metric Name= < metric_name > _ < Table_Name >

|   #   | Counter Metric Name       | Description     | 
| :---: | :-------------------------| :------------- |
|1|table_stat_n_tup_upd_ < Table_Name >|number of rows (tuples) updated| 
|2|table_stat_n_tup_del_ < Table_Name >|number of rows (tuples) deleted|  
|3|table_stat_n_tup_ins_ < Table_Name >  |number of rows (tuples) inserted|
|4|table_stat_n_mod_since_analyze_ < Table_Name >  |Estimated number of rows modified since this table was last analyzed|
|5|table_stat_n_tup_hot_upd_ < Table_Name >     |number of hot update|
|6|table_stat_tup_ins_precent_ < Table_Name > |percent of rows (tuples) inserted|
|7|table_stat_tup_upd_precent_ < Table_Name > |percent of rows (tuples) updated|
|8|table_stat_tup_del_precent_ < Table_Name > |percent of rows (tuples) deleted|
|9|table_stat_total_idx_scan_ < Table_Name > |total number of index scan|
|10|table_stat_total_fts_scan_ < Table_Name >| total number of full table scan (seq scan )|
|11|table_stat_n_live_tup_ < Table_Name > |number of  the live rows (tuples)|
|12|table_stat_n_dead_tup_ < Table_Name > |number of  the dead rows (tuples)| 
|13|table_stat_dead_tup_percent_ < Table_Name > | percent of dead rows (tuples)|
|14|table_stat_autovacuum_count_ < Table_Name > | autovacuum count  |
|15|table_stat_autoanalyze_count_ < Table_Name > |autoanalyze count |                

![](img/Table_metric_dashboard.gif)

### 3- pg_stat_statements (only the top 20 query that consume the DB time / per query id):

**Note**: [pg_stat_statements](https://www.postgresql.org/docs/13/pgstatstatements.html) extension need to be enabled 

the below query to list the top 20 query that consume the DB time 

```
select  queryid,substring(query,1,60) as query , calls, 
round(total_time::numeric, 2) as total_time_Msec, 
round((total_time::numeric/1000), 2) as total_time_sec,
round(mean_time::numeric,2) as avg_time_Msec,
round((mean_time::numeric/1000),2) as avg_time_sec,
round(stddev_time::numeric, 2) as standard_deviation_time_Msec, 
round((stddev_time::numeric/1000), 2) as standard_deviation_time_sec, 
round(rows::numeric/calls,2) rows_per_exec,
round((100 * total_time / sum(total_time) over ())::numeric, 4) as percent
from pg_stat_statements 
order by percent desc limit 20;

```

|   #   | Counter Metric Name       | Description     | 
| :---: | :-------------------------| :-------------: | 
|1|pg_stat_statements_calls_queryid_< queryid >|	Number of times executed|
|2|pg_stat_statements_total_time_msec_queryid_< queryid >|	Total time spent in the statement, in milliseconds||
|3|pg_stat_statements_min_time_msec_queryid_< queryid >|	Minimum time spent in the statement, in milliseconds|	
|4|pg_stat_statements_max_time_msec_queryid_< queryid >|		Maximum time spent in the statement, in milliseconds|	
|5|pg_stat_statements_avg_time_msec_queryid_< queryid >|		Mean time spent in the statement, in milliseconds|	
|6|pg_stat_statements_stddev_time_msec_queryid_< queryid >|		Population standard deviation of time spent in the statement, in milliseconds|	
|7|pg_stat_statements_rows_per_exec_queryid_< queryid >|		number of rows retrieved or affected per execution|	
|8|pg_stat_statements_rows_queryid_< queryid >	|	Total number of rows retrieved or affected by the statement|	
|9|pg_stat_statements_db_time_percent_queryid_< queryid >|		DB time percent consumed by this query|	
|10|pg_stat_statements_shared_blks_hit_queryid_< queryid >|		Total number of shared block cache hits by the statement|	
|11|pg_stat_statements_shared_blks_read_queryid_< queryid >|		Total number of shared blocks read by the statement|	
|12|pg_stat_statements_shared_blks_dirtied_queryid_< queryid >|		Total number of shared blocks dirtied by the statement|	
|13|pg_stat_statements_shared_blks_written_queryid_< queryid >|		Total number of shared blocks written by the statement|	
|14|pg_stat_statements_local_blks_hit_queryid_< queryid >|		Total number of local block cache hits by the statement|	
|15|pg_stat_statements_local_blks_read_queryid_< queryid >|		Total number of local blocks read by the statement|	
|16|pg_stat_statements_local_blks_dirtied_queryid_< queryid >|		Total number of local blocks dirtied by the statement|	
|17|pg_stat_statements_local_blks_written_queryid_< queryid >|		Total number of local blocks written by the statement|	
|18|pg_stat_statements_temp_blks_read_queryid_< queryid >|		Total number of temp blocks read by the statement|	
|19|pg_stat_statements_temp_blks_written_queryid_< queryid >|		Total number of temp blocks written by the statement|	
|20|pg_stat_statements_blk_read_time_msec_queryid_< queryid >|		Total time the statement spent reading blocks, in milliseconds (if track_io_timing is enabled, otherwise zero)|	
|21|pg_stat_statements_blk_write_time_msec_queryid_< queryid >	|	Total time the statement spent writing blocks, in milliseconds (if track_io_timing is enabled, otherwise zero)|	

![](img/Query_Id_metrics_dashboard.gif)

## PG Counter Metrics Dashboards :

There are three type of Dashboard same like the metrics 
```
    1- Dashboard for Database performance 
    2- Dashboard for Table metrics Dashboard (per table)
    3- Dashboard for pg_stat_statements (per query id)
```
the deafult option is to create the dashboard by using the could formation that already provided in the below steps but you still have the option to create custom dashboard please refer to [AWS cloud watch documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/create_dashboard.html)   

**Note**: 
Some metrics use CloudWatch’s Rate Metric Math

CloudWatch’s Rate Metric Math : Returns the rate of change of the metric per second. This is calculated as the difference between the latest data point value and the previous data point value, divided by the time difference in seconds between the two values.

<image src = "img/CloudWatch_Rate.png"></image>

## PG Counter Metrics  Alarms :

PGCM provide cloud formation template that will provide basics alarms ,
you can edit the template to add more alarms, customize alarm Threshold and Period, add Notification etc. please refer to [AWS cloudwatch Alarms documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html)
and [AWS cloudFormation documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cw-alarm.html)

|   #   | Alarm Name      | Description    | 
| :---: | :-------------- | :------------- | 
|1|PGCM_Status_Alarm| PGCM is not working for 3 Min |
|2|invalid_indexes_PGCM_Alarm|invalid indexes count Equal or over 1 for 5 Min|
|3|nactive_Replication_Slot_PGCM_Alarm|Inactive Replication Slot count Equal or over 1 for 15 Min|
|4|Xid_Wraparound_PGCM_Alarm|Xid Percent Towards Wraparound is 50 % for 15 Min|

## Deploying PG Counter Metrics :

### 1- The below steps need to done only one time for each region 

#### 1.1- use the build script to create PGCM’s  lambda ZIP file

```
cd pgcm
sh pgcm_build.sh
```
Example of the output 
```
[Mohamed@dev-dsk pgcm]$ sh build.sh

Removeing existing pgcm_1.8.zip file

zip -r pgcm_1.8.zip pgcm.py rds_config.py tables_config.py scramp/ pg8000/ certs/ asn1crypto/

  adding: pgcm.py (deflated 91%)
  adding: rds_config.py (deflated 52%)
  adding: tables_config.py (deflated 53%)
  adding: scramp/ (stored 0%)
  adding: scramp/__init__.py (deflated 40%)
  adding: scramp/core.py (deflated 76%)
  adding: scramp/_version.py (deflated 71%)
  adding: scramp/utils.py (deflated 56%)
  adding: pg8000/ (stored 0%)
  adding: pg8000/native.py (deflated 68%)
  adding: pg8000/legacy.py (deflated 75%)
  adding: pg8000/exceptions.py (deflated 65%)
  adding: pg8000/converters.py (deflated 74%)
  adding: pg8000/__init__.py (deflated 57%)
  adding: pg8000/core.py (deflated 74%)
  adding: pg8000/_version.py (deflated 72%)
  adding: pg8000/dbapi.py (deflated 76%)
  adding: certs/ (stored 0%)
  adding: certs/commercial/ (stored 0%)
  adding: certs/commercial/rds-ca-2019-root.pem (deflated 29%)
  adding: asn1crypto/ (stored 0%)
  adding: asn1crypto/algos.py (deflated 82%)
  adding: asn1crypto/version.py (deflated 21%)
  adding: asn1crypto/pem.py (deflated 71%)
  adding: asn1crypto/cms.py (deflated 81%)
  adding: asn1crypto/_errors.py (deflated 50%)
  adding: asn1crypto/crl.py (deflated 79%)
  adding: asn1crypto/__init__.py (deflated 65%)
  adding: asn1crypto/core.py (deflated 83%)
  adding: asn1crypto/pkcs12.py (deflated 67%)
  adding: asn1crypto/_types.py (deflated 55%)
  adding: asn1crypto/_ordereddict.py (deflated 64%)
  adding: asn1crypto/_inet.py (deflated 74%)
  adding: asn1crypto/csr.py (deflated 63%)
  adding: asn1crypto/_int.py (deflated 47%)
  adding: asn1crypto/util.py (deflated 79%)
  adding: asn1crypto/x509.py (deflated 80%)
  adding: asn1crypto/parser.py (deflated 74%)
  adding: asn1crypto/_iri.py (deflated 70%)
  adding: asn1crypto/_teletex_codec.py (deflated 77%)
  adding: asn1crypto/tsp.py (deflated 76%)
  adding: asn1crypto/pdf.py (deflated 66%)
  adding: asn1crypto/keys.py (deflated 81%)
  adding: asn1crypto/ocsp.py (deflated 83%)

Generated new Lambda file pgcm_1.8.zip

Archive:  pgcm_1.8.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   123698  03-26-2021 18:25   pgcm.py
      935  03-26-2021 18:25   rds_config.py
      343  03-26-2021 18:25   tables_config.py
        0  03-26-2021 18:25   scramp/
      176  03-26-2021 18:25   scramp/__init__.py
    18205  03-26-2021 18:25   scramp/core.py
    18516  03-26-2021 18:25   scramp/_version.py
      655  03-26-2021 18:25   scramp/utils.py
        0  03-26-2021 18:25   pg8000/
     7569  03-26-2021 18:25   pg8000/native.py
    24407  03-26-2021 18:25   pg8000/legacy.py
      940  03-26-2021 18:25   pg8000/exceptions.py
    17071  03-26-2021 18:25   pg8000/converters.py
     4118  03-26-2021 18:25   pg8000/__init__.py
    33529  03-26-2021 18:25   pg8000/core.py
    15795  03-26-2021 18:25   pg8000/_version.py
    27190  03-26-2021 18:25   pg8000/dbapi.py
        0  03-26-2021 18:25   certs/
        0  03-26-2021 18:25   certs/commercial/
     1456  03-26-2021 18:25   certs/commercial/rds-ca-2019-root.pem
        0  03-26-2021 18:25   asn1crypto/
    35611  03-26-2021 18:25   asn1crypto/algos.py
      152  03-26-2021 18:25   asn1crypto/version.py
     6145  03-26-2021 18:25   asn1crypto/pem.py
    27294  03-26-2021 18:25   asn1crypto/cms.py
     1070  03-26-2021 18:25   asn1crypto/_errors.py
    16104  03-26-2021 18:25   asn1crypto/crl.py
     1219  03-26-2021 18:25   asn1crypto/__init__.py
   170559  03-26-2021 18:25   asn1crypto/core.py
     4566  03-26-2021 18:25   asn1crypto/pkcs12.py
      939  03-26-2021 18:25   asn1crypto/_types.py
     4533  03-26-2021 18:25   asn1crypto/_ordereddict.py
     4661  03-26-2021 18:25   asn1crypto/_inet.py
     2142  03-26-2021 18:25   asn1crypto/csr.py
      494  03-26-2021 18:25   asn1crypto/_int.py
    21873  03-26-2021 18:25   asn1crypto/util.py
    93421  03-26-2021 18:25   asn1crypto/x509.py
     8853  03-26-2021 18:25   asn1crypto/parser.py
     8733  03-26-2021 18:25   asn1crypto/_iri.py
     5053  03-26-2021 18:25   asn1crypto/_teletex_codec.py
     7827  03-26-2021 18:25   asn1crypto/tsp.py
     2250  03-26-2021 18:25   asn1crypto/pdf.py
    36788  03-26-2021 18:25   asn1crypto/keys.py
    19024  03-26-2021 18:25   asn1crypto/ocsp.py
---------                     -------
   773914                     44 files
   
[Mohamed@dev-dsk  pgcm]$

```

#### 1.2- Create a S3 bucket (or reuse one you already have) for hosting the ZIP files

-> Set [AWS_PROFILE](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) as environment variable 

```
export AWS_PROFILE= < >
```


-> Create S3 bucket called pgcm

```
aws s3 mb s3://pgcm --profile ${AWS_PROFILE} --output table
```
-> upload pgcm_< version >.zip to the S3 bucket

```
aws s3 cp <>.zip s3://pgcm/ --profile ${AWS_PROFILE} --output table

EX:
aws s3 cp pgcm_1.8.zip s3://pgcm/ --profile ${AWS_PROFILE} --output table
```

-> check the uploaded zip file

```
aws s3 ls s3://pgcm/  --human-readable --profile ${AWS_PROFILE} --output table
```

**Note**: 
- To be able to finish the next steps you need to get some information  about the database like VPC , Security Group , Port and DB Resource Id.
- you will need the DB Resource Id if you will use the IADM DB Auth 

set environment variables: 

-> Set [AWS_PROFILE](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) as environment variable 

```
export AWS_PROFILE= < >
```
-> set the RDS PostgreSQL DB INSTANCE IDENTIFIER as environment variable
```
export DB_INSTANCE_IDENTIFIER=
```
-> set AWS Region as environment variable

```
export REGION=
```

-> run below AWS cli to get the infomation 

```
aws rds describe-db-instances --db-instance-identifier ${DB_INSTANCE_IDENTIFIER} --profile ${AWS_PROFILE}  | grep VpcId
aws rds describe-db-instances --profile ${AWS_PROFILE} | grep VpcSecurityGroupId
aws rds describe-db-instances --db-instance-identifier ${DB_INSTANCE_IDENTIFIER} --profile ${AWS_PROFILE}  | grep SubnetIdentifier
aws rds describe-db-instances --db-instance-identifier ${DB_INSTANCE_IDENTIFIER} --profile ${AWS_PROFILE} | grep -w "Port"
aws rds describe-db-instances --db-instance-identifier ${DB_INSTANCE_IDENTIFIER} --profile ${AWS_PROFILE} | grep DbiResourceId

```

-> use the above information to set below environment variables

```
export VPC_ID= < >
export DB_PORT= < >
export SUBNET_ID_1= < >
export SUBNET_ID_2= < >
export SUBNET_ID_3= < > 
export SUBNET_ID_4= < >
export SECURITYGROUPID= < >
```

#### 1.3- Create VPC Endpoint for cloud watch so Lambda can connect over private link

```
aws ec2 create-vpc-endpoint  \
--vpc-endpoint-type  Interface \
--vpc-id ${VPC_ID} \
--subnet-ids ${SUBNET_ID_1} ${SUBNET_ID_2} ${SUBNET_ID_3} \
--security-group-id  ${SECURITYGROUPID} \
--service-name com.amazonaws.${REGION}.monitoring \
--private-dns-enabled \
--profile ${AWS_PROFILE} --output table 
```
```
aws ec2 describe-vpc-endpoint-services \
--service-names com.amazonaws.${REGION}.monitoring \
--profile ${AWS_PROFILE} --output table
```

#### 1.4- Create VPC Endpoint for AWS Secrets Manager if you will use Secrets Manager as authentication type

```
aws ec2 create-vpc-endpoint  \
--vpc-endpoint-type  Interface \
--vpc-id ${VPC_ID} \
--subnet-ids ${SUBNET_ID_1} ${SUBNET_ID_2} ${SUBNET_ID_3} \
--security-group-id  ${SECURITYGROUPID} \
--service-name com.amazonaws.${REGION}.secretsmanager \
--private-dns-enabled \
--profile ${AWS_PROFILE} --output table
```

```
aws ec2 describe-vpc-endpoint-services \
--service-names com.amazonaws.${REGION}.secretsmanager \
--profile ${AWS_PROFILE} --output table
```

#### 1.5- Update the database Security Group 
To allow lambda to connect the DB  and also allow lambda to connect to cloud watch from the same VPC .

**Note**: Assuming that you have one Security Group for all the databases in same region and using same port for all the databases , if you are using diffrent port or Security Group you have to update each Security Group with the DB port 

-> get the VPC CIDR

```
aws ec2 describe-vpcs \
--vpc-ids ${VPC_ID} \
--query "Vpcs[*].[CidrBlock]" \
--profile ${AWS_PROFILE} --output table
```
-> set below env variable

```
export VPC_CIDR=  < >
echo $VPC_CIDR

```

-> Add cloud watch port 

```
aws ec2 authorize-security-group-ingress  \
--group-id ${SECURITYGROUPID}  \
--protocol tcp \
--port 443 \
--cidr ${VPC_CIDR} \
--profile ${AWS_PROFILE} --output table
```

-> Add the DB port 

```
aws ec2 authorize-security-group-ingress  \
--group-id ${SECURITYGROUPID}  \
--protocol tcp \
--port ${DB_PORT} \
--cidr ${VPC_CIDR} \
--profile ${AWS_PROFILE} --output table  
```

```
 aws ec2 describe-security-groups --group-ids ${SECURITYGROUPID} \
 --profile ${AWS_PROFILE} --output table
```

### 2- For each Database follow below steps 

#### 2.1 Create a database user 
**Notes**:
- The default  database user will be user_pgcm if you want to change it you need to edit the DB user creation script
- you need [psql](https://www.postgresql.org/docs/10/app-psql.html) to be able to connect to the postgresql DB and run DB user creation  script


--> If the AWS Secrets Manager or username/password will be used as authentication type then use create_database_user_pwd_pgcm.sql to create the DB user .

login to the DB using the master user then execute below script 

```
cd scripts
```
```
psql -h [hostname or RDS endpoint] -p [Port] -d [Database name ] -U [user name]
```
```
\i  create_database_user_pwd_pgcm.sql
```

--> If IAM Database Authentication will be used as authentication type then use  create_database_user_iam_pgcm.sql script to create the DB user .

1- Enabling IAM database authentication 

you have to Enable the IAM database authentication to use the IAM Database Authentication.
please refere to RDS Doc for [how to enable IAM DB authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Enabling.html)

Also you you can use AWS CLI to check and enable the IAMDB DB authentication

-> Set [AWS_PROFILE](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) as environment variable 

```
export AWS_PROFILE= < >
```

For Aurora PostgreSQL:
```
->  set Aurora PostgreSQL CLUSTER IDENTIFIER as environment variable 

export APG_CLUSTER_IDENTIFIER= < >

-> To check the IADM DB authentication stattus 

aws rds  describe-db-clusters --db-cluster-identifier ${APG_CLUSTER_IDENTIFIER} \
--profile ${AWS_PROFILE} --output table | grep IAMDatabaseAuthenticationEnabled


-> Enable the IAMDB DB authentication 

aws rds modify-db-cluster --db-cluster-identifier ${APG_CLUSTER_IDENTIFIER} \
--enable-iam-database-authentication  --apply-immediately \
--profile ${AWS_PROFILE} --output table

aws rds  describe-db-clusters --db-cluster-identifier ${APG_CLUSTER_IDENTIFIER} --profile ${AWS_PROFILE} --output table | grep available


```

For RDS PostgreSQL:

```

->  Set RDS PostgreSQL DB INSTANCE IDENTIFIER as environment variable 

export DB_INSTANCE_IDENTIFIER= < >

-> Enable the IAMDB DB authentication 

aws rds describe-db-instances --db-instance-identifier ${DB_INSTANCE_IDENTIFIER} \
--profile ${AWS_PROFILE} --output table | grep IAMDatabaseAuthenticationEnabled

aws rds modify-db-instance --db-instance-identifier ${DB_INSTANCE_IDENTIFIER} \
--enable-iam-database-authentication  --apply-immediately \
--profile ${AWS_PROFILE} --output table

```

2- Create DB user :

login to the DB using the master user then execute below script 

```
cd scripts
```
```
psql -h [hostname or RDS endpoint] -p [Port] -d [Database name ] -U [user name]
```
```
\i  create_database_user_iam_pgcm.sql
```

#### 2.2 Use cloudformation to deploy the PGCM lambda function

This cloudformation will create below

```
1- lambda function
2- IAM role and policies 
3- AWS secret if you AWS Secrets Manager got selected as authentication type
4- CLoud watch Dashbord for the database Metrics  
```
cloud formation template location and name : CF/PGCM_lambda_CF.yaml

Creating a stack using the AWS CloudFormation console

1- Open the AWS CloudFormation console at https://console.aws.amazon.com/cloudformation and select Create a new stack 

2- choose a stack template:

On the Specify template page, choose a stack template by Uploading a template file
Select a CloudFormation template on your local computer. 

3- on Specify stack details

Enter the stack name :  < DB_INSTANCE_IDENTIFIER >-PGCM 

then update the Parameters 

<image src = "img/CF_Create_Stack_1.png"></image> 
<image src = "img/CF_Create_Stack_2.png"></image>    
<image src = "img/CF_Create_Stack_3.png"></image>    
<image src = "img/CF_Create_Stack_4.png"></image>        


#### 2.3 Use cloudformation to deploy the PGCM table metrics dashboard (per table)
This cloudformation will create CLoud watch Dashbord for table metric.
You need to use this cloudformation  for each table you need to creat dashboard of it .

cloud formation template location and name : CF/PGCM_Table_metrics_Dashboard.yaml

1- Open the AWS CloudFormation console at https://console.aws.amazon.com/cloudformation and select Create a new stack 

2- choose a stack template:
   On the Specify template page, choose a stack template by Uploading a template file
   Select a CloudFormation template on your local computer. 

3- on Specify stack details
Enter the stack name :  < DB_INSTANCE_IDENTIFIER >-< Table_Name >-Table-PGCM 

then update the Parameters 

<image src = "img/CF_Create_Stack_table_1.png"></image> 
<image src = "img/CF_Create_Stack_table_2.png"></image> 

#### 2.4 Use cloudformation to deploy the PGCM query metrics dashboard (per query ID)

use below query to list the top 20 query that consume the DB time and select the query ID that you want to create Dashboared for 

```
select  queryid,substring(query,1,60) as query , calls, 
round(total_time::numeric, 2) as total_time_Msec, 
round((total_time::numeric/1000), 2) as total_time_sec,
round(mean_time::numeric,2) as avg_time_Msec,
round((mean_time::numeric/1000),2) as avg_time_sec,
round(stddev_time::numeric, 2) as standard_deviation_time_Msec, 
round((stddev_time::numeric/1000), 2) as standard_deviation_time_sec, 
round(rows::numeric/calls,2) rows_per_exec,
round((100 * total_time / sum(total_time) over ())::numeric, 4) as percent
from pg_stat_statements 
order by percent desc limit 20;
```

cloud formation template location and name : CF/PGCM_QueryId_metrics_Dashboard.yaml

1- Open the AWS CloudFormation console at https://console.aws.amazon.com/cloudformation and select Create a new stack 

2- choose a stack template:
   On the Specify template page, choose a stack template by Uploading a template file
   Select a CloudFormation template on your local computer. 

3- on Specify stack details

Enter the stack name :  < DB_INSTANCE_IDENTIFIER >- < query id >-queryid-PGCM 

then update the Parameters

<image src = "img/CF_Create_Stack_queryid_1.png"></image> 
<image src = "img/CF_Create_Stack_queryid_2.png"></image> 

#### 2.5 Use cloudformation to deploy cloudwatch alrams

**Notes**: this cloud formation template will provide basics alarms ,
you can edit the template to add more alarms, customize alarm Threshold and Period, add Notification etc. 

cloud formation template location and name : CF/pgcm_alarm_cf.yaml

1- Open the AWS CloudFormation console at https://console.aws.amazon.com/cloudformation and select Create a new stack 

2- choose a stack template:
   On the Specify template page, choose a stack template by Uploading a template file
   Select a CloudFormation template on your local computer. 

3- on Specify stack details

Enter the stack name :  < DB_INSTANCE_IDENTIFIER >-PGCM-Alarm 

then update the Parameters


## FAQ :
- will PGCM change or access my data ?

> No, PGCM will not change or access your data,  PGCM will read postgresql performance data only as PCGM DB user have only pg_monitor role
pg_monitor	Read/execute various monitoring views and functions. This role is a member of pg_read_all_settings, pg_read_all_stats and pg_stat_scan_tables.

- will PGCM flood my DB with many connection ? 

>No, PGCM DB user is limited by two session only so PGCM will not flood your DB with connection PGCM will start to fail if there is 2 session in the DB 

- will PGCM cause any long running query ?

> No , PGCM will set statement_timeout = 10sec in session level , if there is any query take more than 10 sec it will be terminated automatically

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

