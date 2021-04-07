# +-----------------------------------------------------------------------------------+
# |                            PG Counter Metrics (PGCM) V1.8                         |
# |  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.               |
# |  SPDX-License-Identifier: Apache-2.0                                              |
# |  -- Author : Mohamed Ali                                                          |
# |  -- Script Name:  pgcm.py                                                         |
# |  -- Create Date : 23 April 2020                                                   |
# |  -- Description : Pg Counter Metrics ( PGCM ) is a tool for publishing            |
# |  --               PostgreSQL performance data to CloudWatch                       |
# |  -- Changelog :                                                                   |
# |       https://github.com/awslabs/pg-counter-metrics/blob/main/CHANGELOG.md        |                                                    |
# +-----------------------------------------------------------------------------------+
import sys
import logging
import pg8000
import boto3
import rds_config
import json
import tables_config
import ssl
import os


#rds settings
rds_host  = rds_config.rds_host
name = rds_config.db_username
db_name = rds_config.db_name
region = rds_config.db_region
port = rds_config.db_port
auth_type = rds_config.auth_type
secret_name = rds_config.db_secret_name
username_password = rds_config.username_password
metric_name=rds_config.metric_name



#tables_config
schema_list = tables_config.schema_list
tables_list = tables_config.tables_list

#DB connection over SSL 
#creating a global SSL context
sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
sslctx.load_verify_locations(rds_config.CA_CERT)
# to disable SSL remove # befor sslctx = None  
# sslctx = None


query_percent_towards_wraparound = "SELECT  ROUND(100*(max(age(datfrozenxid))/2000000000::float)) AS percent_towards_wraparound  from  pg_database ; "
query_queries_canceled_due_to_lock_timeouts  = "select confl_lock from pg_stat_database_conflicts where datname = (select current_database()); "
query_queries_canceled_due_to_lock_deadlocks = "select confl_deadlock from pg_stat_database_conflicts where datname = (select current_database()); "
query_idle_in_transaction_sessions = "select count (*) from pg_stat_activity where state = 'idle in transaction'; "
query_idle_sessions = "select count (*) from pg_stat_activity where state = 'idle';"
query_idle_in_transaction_aborted_sessions = "select count (*) from pg_stat_activity where state = 'idle in transaction (aborted)'; "
query_active_sessions = "select count (*) from pg_stat_activity where state = 'active'; "
query_Inactive_replication_slots = "select count (*) from pg_replication_slots where active = false; "
query_invalid_indexes = "select count (*) as count_of_invalid_indxes from pg_index WHERE pg_index.indisvalid = false ; "
query_deadlocks ="select count (deadlocks) from  pg_stat_database;"
query_total_connections ="select sum (numbackends) from pg_stat_database;"
query_max_connections = "SELECT setting::float AS max_connections FROM pg_settings WHERE name = 'max_connections';"
query_autovacuum_freeze_max_age = "select setting::float AS autovacuum_freeze_max_age FROM pg_catalog.pg_settings WHERE name = 'autovacuum_freeze_max_age';"
query_oldest_xid = "SELECT max(age(datfrozenxid)) oldest_current_xid FROM pg_database;"   
query_autovacuum_count_per_min = "select  count(*) from pg_stat_all_tables   where to_char(last_autovacuum, 'YYYY-MM-DD hh24:MI') = to_char(STATEMENT_TIMESTAMP() , 'YYYY-MM-DD hh24:MI') ;"
query_autovacuum_count_per_hour = "select  count(*) from pg_stat_all_tables   where to_char(last_autovacuum, 'YYYY-MM-DD hh24') = to_char(STATEMENT_TIMESTAMP() , 'YYYY-MM-DD hh24') ;"
query_autovacuum_count_per_day = "select  count(*) from pg_stat_all_tables   where to_char(last_autovacuum, 'YYYY-MM-DD') = to_char(STATEMENT_TIMESTAMP() , 'YYYY-MM-DD') ;"
query_autoanalyze_count_per_min = "select count(*) from pg_stat_all_tables   where to_char(last_autoanalyze, 'YYYY-MM-DD hh24:MI') = to_char(STATEMENT_TIMESTAMP() , 'YYYY-MM-DD hh24:MI') ;"
query_autoanalyze_count_per_hour = "select count(*) from pg_stat_all_tables where to_char(last_autoanalyze, 'YYYY-MM-DD hh24') = to_char(STATEMENT_TIMESTAMP() , 'YYYY-MM-DD hh24') ;"
query_autoanalyze_count_per_day = "select count(*) from pg_stat_all_tables where to_char(last_autoanalyze, 'YYYY-MM-DD') = to_char(STATEMENT_TIMESTAMP() , 'YYYY-MM-DD') ;"
query_total_DB_size_in_GB = "select round(sum(pg_database_size(pg_database.datname))/1024/1024/1024) as Total_Database_size_GB FROM pg_database;"
query_Active_replication_slots = "select count (*) from pg_replication_slots where active = true;"
query_blocked_sessions = "select count(*) from pg_stat_activity where cardinality(pg_blocking_pids(pid)) > 0 ;"
query_wait_event = "select row_to_json(t) from (select array_to_json(array_agg(row_to_json(d))) from (SELECT coalesce(wait_event,'Cpu') as wait_event , count(*) FROM pg_stat_activity group by wait_event ) d ) t;"
query_table_stat = """select row_to_json(t) from (select array_to_json(array_agg(row_to_json(d))) from ( 
Select  schemaname as schema_name, relname as "Table_Name", coalesce(seq_scan,0) total_fts_scan , coalesce(idx_scan,0) total_idx_scan,
coalesce(trunc((idx_scan::numeric/NULLIF((idx_scan::numeric+seq_scan::numeric),0)) * 100,2),0) as "IDX_scan_%", 
coalesce(trunc((seq_scan::numeric/NULLIF((idx_scan::numeric+seq_scan::numeric),0)) * 100,2),0) as "FTS_scan_%", 
coalesce(n_live_tup,0) as n_live_tup, coalesce(n_dead_tup,0) as n_dead_tup,
coalesce(trunc((n_dead_tup::numeric/NULLIF(n_live_tup::numeric,0)) * 100,2),0) as "dead_tup_%",
coalesce(n_tup_ins,0) as n_tup_ins,coalesce(n_tup_upd,0) as n_tup_upd, coalesce(n_tup_del,0) as n_tup_del,
coalesce(n_mod_since_analyze,0) as n_mod_since_analyze,
coalesce(trunc((n_tup_ins::numeric/NULLIF((n_tup_ins::numeric+n_tup_upd::numeric+n_tup_del::numeric),0)) * 100,2),0) as "tup_ins_%",
coalesce(trunc((n_tup_upd::numeric/NULLIF((n_tup_ins::numeric+n_tup_upd::numeric+n_tup_del::numeric),0)) * 100,2),0) as "tup_upd_%",
coalesce(trunc((n_tup_del::numeric/NULLIF((n_tup_ins::numeric+n_tup_upd::numeric+n_tup_del::numeric),0)) * 100,2),0) as "tup_del_%",
coalesce(n_tup_hot_upd,0) as n_tup_hot_upd,coalesce(autovacuum_count,0) as autovacuum_count ,coalesce(autoanalyze_count,0) as autoanalyze_count
from pg_stat_all_tables
where  schemaname in """ + schema_list +"""
and relname in """ + tables_list +"""
) d ) t;"""
query_oldest_open_transaction = """select coalesce(round((hs + ms + s)::numeric,2),0) as max_xact_duration_in_s
from (select 
EXTRACT (HOUR FROM  max_xact_duration::time) * 60*60 as hs,
EXTRACT (MINUTES FROM max_xact_duration::time) * 60 as ms,
EXTRACT (SECONDS from max_xact_duration::time) as s
from (SELECT max(now() - xact_start )
as max_xact_duration 
FROM pg_stat_activity 
WHERE state = 'active' 
and xact_start is not null
and query not like '%autovacuum:%'
and query not like '%vacuum%') as max ) as s ;"""
query_n_tables_eligible_for_autovacuum = """SELECT n_tables_eligible_for_autovacuum from 
( WITH vbt AS (SELECT setting AS autovacuum_vacuum_threshold FROM pg_settings WHERE name = 'autovacuum_vacuum_threshold')
, vsf AS (SELECT setting AS autovacuum_vacuum_scale_factor FROM pg_settings WHERE name = 'autovacuum_vacuum_scale_factor')
, fma AS (SELECT setting AS autovacuum_freeze_max_age FROM pg_settings WHERE name = 'autovacuum_freeze_max_age')
, sto AS (select opt_oid, split_part(setting, '=', 1) as param, split_part(setting, '=', 2) as value from (select oid opt_oid, unnest(reloptions) setting from pg_class) opt)
SELECT coalesce(count (*),0) as n_tables_eligible_for_autovacuum
FROM pg_class c join pg_namespace ns on ns.oid = c.relnamespace
join pg_stat_all_tables stat on stat.relid = c.oid
join vbt on (1=1) join vsf on (1=1) join fma on (1=1)
left join sto cvbt on cvbt.param = 'autovacuum_vacuum_threshold' and c.oid = cvbt.opt_oid
left join sto cvsf on cvsf.param = 'autovacuum_vacuum_scale_factor' and c.oid = cvsf.opt_oid
left join sto cfma on cfma.param = 'autovacuum_freeze_max_age' and c.oid = cfma.opt_oid
WHERE c.relkind = 'r' and nspname <> 'pg_catalog'
and (age(relfrozenxid) >= coalesce(cfma.value::float, autovacuum_freeze_max_age::float)
or
coalesce(cvbt.value::float, autovacuum_vacuum_threshold::float) + coalesce(cvsf.value::float,autovacuum_vacuum_scale_factor::float) * c.reltuples <= n_dead_tup
-- or 1 = 1
)) as s;"""
query_not_granted_lock  = 'SELECT coalesce(count(*),0) as "not_granted_lock" FROM pg_locks WHERE NOT GRANTED;'
query_lock_mode = 'select row_to_json(t) from(select array_to_json(array_agg(row_to_json(d)))  from (SELECT mode as lock_mode , count(*) FROM pg_locks group by mode) d) t ;'
query_lock_type = 'select row_to_json(t) from(select array_to_json(array_agg(row_to_json(d)))  from (SELECT locktype as lock_type , count(*) FROM pg_locks group by locktype) d) t ;'
query_xact_commit = 'select xact_commit from  pg_stat_database where datname = (select current_database());'
query_xact_rollback =  'select xact_rollback from  pg_stat_database where datname = (select current_database());'
query_xact_commit_ratio = 'select 100 * xact_commit / (xact_commit + xact_rollback) as commit_ratio from  pg_stat_database where datname = (select current_database());'
query_tup_returned = 'select tup_returned from  pg_stat_database where datname = (select current_database());'
query_tup_fetched = 'select tup_fetched from  pg_stat_database where datname = (select current_database());'
query_tup_updated = 'select tup_updated from  pg_stat_database where datname = (select current_database());'
query_tup_deleted = 'select tup_deleted from  pg_stat_database where datname = (select current_database());'
query_tup_inserted = 'select tup_inserted from  pg_stat_database where datname = (select current_database());'
query_checkpoints_requested = 'select checkpoints_req as "checkpoints_requested" from pg_stat_bgwriter;'
query_checkpoints_timed = 'select checkpoints_timed from pg_stat_bgwriter;'
query_Oldest_Replication_Slot_Lag_gb_behind = """select
coalesce(max(round(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) / 1024 / 1024 / 1024, 2)),0) AS Oldest_Replication_Slot_Lag_GB_behind
from pg_replication_slots;"""
query_oldest_open_idl_in_transaction = """select coalesce(round((hs + ms + s)::numeric,2),0) as max_xact_duration_in_s
from (select 
EXTRACT (HOUR FROM  max_xact_duration::time) * 60*60 as hs,
EXTRACT (MINUTES FROM max_xact_duration::time) * 60 as ms,
EXTRACT (SECONDS from max_xact_duration::time) as s
from (SELECT max(now() - xact_start )
as max_xact_duration 
FROM pg_stat_activity 
WHERE state  = 'idle in transaction'
and xact_start is not null
and query not like '%autovacuum:%'
and query not like '%vacuum%') as max ) as s ;"""
query_Oldest_Replication_Slot_Lag_gb_behind_per_slot = """select row_to_json(t) from (select array_to_json(array_agg(row_to_json(d))) from (
select slot_name,
coalesce(round(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) / 1024 / 1024 / 1024, 2),0) AS Oldest_Replication_Slot_Lag_GB_behind
from pg_replication_slots
) d ) t;"""
query_count_replication_slots = "select count (*) from pg_replication_slots;"
query_pg_stat_statements = """select row_to_json(t) from (select array_to_json(array_agg(row_to_json(d))) from  ( select queryid , calls, 
round(total_time::numeric, 2) as "total_time_msec", 
round(min_time::numeric, 2) as "min_time_msec", 
round(max_time::numeric, 2) as "max_time_msec", 
round(mean_time::numeric,2) as "avg_time_msec",
round(stddev_time::numeric, 2) as "stddev_time_msec", 
round(rows::numeric/calls,2) as "rows_per_exec",
rows,
round((100 * total_time / sum(total_time) over ())::numeric, 2) as "db_time_percent",
shared_blks_hit,
shared_blks_read,
shared_blks_dirtied,
shared_blks_written,
local_blks_hit,
local_blks_read,
local_blks_dirtied,
local_blks_written,
temp_blks_read,
temp_blks_written,
round(blk_read_time::numeric, 2) as"blk_read_time_msec" ,
round(blk_write_time::numeric, 2) as "blk_write_time_msec"
from pg_stat_statements 
order by db_time_percent desc limit 20 ) d ) t;"""
query_pg_stat_statements_extension = "select count (*) FROM pg_catalog.pg_extension  where extname = 'pg_stat_statements';"
query_db_load_cpu = """select coalesce(count(*),'0') as  count_of_sessions_waiting_on_CPU
FROM pg_stat_activity 
where wait_event is null and state = 'active' group by wait_event ;"""
query_db_load_none_cpu = """select coalesce(sum(count),'0') as count_of_sessions_waiting_on_None_CPU
from (SELECT count(*) as count
FROM pg_stat_activity  
where wait_event is not null and state = 'active' 
group by wait_event) as c;"""
query_bgwriter_buffers_clean = 'select buffers_clean from pg_stat_bgwriter;'
query_bgwriter_buffers_backend = 'select buffers_backend from pg_stat_bgwriter;'
query_bgwriter_maxwritten_clean = 'select maxwritten_clean from pg_stat_bgwriter;'
query_oldest_mxid="SELECT max(mxid_age(datminmxid)) oldest_current_mxid FROM pg_database ;"
query_autovacuum_multixact_freeze_max_age= "select setting::float AS autovacuum_multixact_freeze_max_age FROM pg_catalog.pg_settings WHERE name = 'autovacuum_multixact_freeze_max_age';"

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger_debug = logging.getLogger("pgcm")
logger_debug.setLevel(logging.INFO)
#To enable the debug mode remove the # from the below line and add # to the above line "logger_debug.setLevel(logging.INFO)"
#logger_debug.setLevel(logging.DEBUG)
        
def handler(event, context):
    logger.info( "Starting PG metric Process on " + rds_host)
    logger.info( "Metric Dimension Name: "+ metric_dimension_name)
    logger.info( "Database: " + db_name)
    logger.info( "Database User Name: " + name)
    logger.info( "Database Port: " + str(port))
    logger.info( "schema list: " + schema_list)
    logger.info( "tables list: " + tables_list)    
    try:
        logger.info("-----------------------------")
        logger.info("Test the database connection")
        logger.info("-----------------------------")
        if auth_type == 'password':
            logger.info("Using clear password to connect to the DB")
            token = username_password
            logger_debug.debug("the password: " + token)
        elif auth_type == 'secret_manager':
            logger.info("Using the AWS secret manager to get the password")
            secretValues=json.loads(get_secret())
            token = secretValues['password']
            logger_debug.debug(secretValues)
            logger_debug.debug("the password: " + token)
        else:
            logger.info("Using the IAM DB authentication to create an authentication token")
            client = boto3.client("rds",region_name=region)
            token = client.generate_db_auth_token(rds_host,port, name)
            logger_debug.debug("the password is " + token)
        conn = pg8000.dbapi.connect(database=db_name, host=rds_host, user=name, password=token, port=port, ssl_context=sslctx, timeout=10)
    except (Exception) as error:
        logger.error(error)
        putErrorMetric()
        return None
    logger.info("SUCCESS: Connection to RDS postgres instance succeeded")
    try:
        logger.info("------------------------------")
        logger.info("Sarting the queries execution")
        logger.info("------------------------------")
        
        logger_debug.debug("Executing result_percent_towards_wraparound")
        result_percent_towards_wraparound = executeSQL(conn, query_percent_towards_wraparound)
        logger_debug.debug("result_percent_towards_wraparound = " + str(result_percent_towards_wraparound[0][0]))

        logger_debug.debug("Executing result_queries_canceled_due_to_lock_timeouts")
        result_queries_canceled_due_to_lock_timeouts  = executeSQL(conn, query_queries_canceled_due_to_lock_timeouts)
        logger_debug.debug("result_queries_canceled_due_to_lock_timeouts = " + str(result_queries_canceled_due_to_lock_timeouts[0][0]))

        logger_debug.debug("Executing result_queries_canceled_due_to_lock_deadlocks")
        result_queries_canceled_due_to_lock_deadlocks =  executeSQL(conn, query_queries_canceled_due_to_lock_deadlocks)
        logger_debug.debug("result_queries_canceled_due_to_lock_deadlocks = " + str(result_queries_canceled_due_to_lock_deadlocks[0][0]))

        logger_debug.debug("Executing result_idle_in_transaction_sessions")
        result_idle_in_transaction_sessions = executeSQL(conn, query_idle_in_transaction_sessions)
        logger_debug.debug("result_idle_in_transaction_sessions = " + str(result_idle_in_transaction_sessions[0][0]))

        logger_debug.debug("Executing result_idle_sessions")
        result_idle_sessions = executeSQL(conn, query_idle_sessions)
        logger_debug.debug("result_idle_sessions = " + str(result_idle_sessions[0][0]))

        logger_debug.debug("Executing result_idle_in_transaction_aborted_sessions")
        result_idle_in_transaction_aborted_sessions = executeSQL(conn, query_idle_in_transaction_aborted_sessions)
        logger_debug.debug("result_idle_in_transaction_aborted_sessions = " + str(result_idle_in_transaction_aborted_sessions[0][0]))

        logger_debug.debug("Executing result_active_sessions")
        result_active_sessions = executeSQL(conn, query_active_sessions)
        logger_debug.debug("result_active_sessions = " + str(result_active_sessions[0][0]))

        logger_debug.debug("Executing result_Inactive_replication_slot")
        result_Inactive_replication_slot = executeSQL(conn, query_Inactive_replication_slots)
        logger_debug.debug("result_Inactive_replication_slot = " + str(result_Inactive_replication_slot[0][0]))

        logger_debug.debug("Executing result_invalid_indexes")
        result_invalid_indexes = executeSQL(conn, query_invalid_indexes)
        logger_debug.debug("result_invalid_indexes = " + str(result_invalid_indexes[0][0]))

        logger_debug.debug("Executing result_deadlocks")
        result_deadlocks = executeSQL(conn, query_deadlocks)
        logger_debug.debug("result_deadlocks = " + str(result_deadlocks[0][0]))

        logger_debug.debug("Executing result_total_connections")
        result_total_connections = executeSQL(conn, query_total_connections)
        logger_debug.debug("result_total_connections = " + str(result_total_connections[0][0]))

        logger_debug.debug("Executing result_max_connections")
        result_max_connections = executeSQL(conn, query_max_connections)
        logger_debug.debug("result_max_connections = " + str(result_max_connections[0][0]))

        logger_debug.debug("Executing result_connections_utilization")
        result_connections_utilization = round(100*( result_total_connections[0][0] / result_max_connections[0][0]  ),2)
        logger_debug.debug("result_connections_utilization = " + str(result_connections_utilization))

        logger_debug.debug("Executing result_autovacuum_freeze_max_age")
        result_autovacuum_freeze_max_age = executeSQL(conn, query_autovacuum_freeze_max_age)
        logger_debug.debug("result_autovacuum_freeze_max_age = " + str(result_autovacuum_freeze_max_age[0][0]))

        logger_debug.debug("Executing result_oldest_xid")
        result_oldest_xid = executeSQL(conn, query_oldest_xid)
        logger_debug.debug("result_oldest_xid = " + str(result_oldest_xid[0][0]))

        logger_debug.debug("Executing result_percent_towards_emergency_autovacuum")
        result_percent_towards_emergency_autovacuum  = round(100*( result_oldest_xid[0][0]/result_autovacuum_freeze_max_age[0][0] ),2)
        logger_debug.debug("result_percent_towards_emergency_autovacuum = " + str(result_percent_towards_emergency_autovacuum))

        logger_debug.debug("Executing result_autovacuum_count_per_min")
        result_autovacuum_count_per_min = executeSQL(conn, query_autovacuum_count_per_min)
        logger_debug.debug("result_autovacuum_count_per_min = " + str(result_autovacuum_count_per_min[0][0]))

        logger_debug.debug("Executing result_autovacuum_count_per_hour")
        result_autovacuum_count_per_hour = executeSQL(conn, query_autovacuum_count_per_hour)
        logger_debug.debug("result_autovacuum_count_per_hour = " + str(result_autovacuum_count_per_hour[0][0]))

        logger_debug.debug("Executing result_autovacuum_count_per_day")
        result_autovacuum_count_per_day = executeSQL(conn, query_autovacuum_count_per_day)
        logger_debug.debug("result_autovacuum_count_per_day = " + str(result_autovacuum_count_per_day[0][0]))

        logger_debug.debug("Executing result_autoanalyze_count_per_min")
        result_autoanalyze_count_per_min = executeSQL(conn, query_autoanalyze_count_per_min)
        logger_debug.debug("result_autoanalyze_count_per_min = " + str(result_autoanalyze_count_per_min[0][0]))

        logger_debug.debug("Executing result_autoanalyze_count_per_hour")
        result_autoanalyze_count_per_hour = executeSQL(conn, query_autoanalyze_count_per_hour)
        logger_debug.debug("result_autoanalyze_count_per_hour = " + str(result_autoanalyze_count_per_hour[0][0]))

        logger_debug.debug("Executing result_autoanalyze_count_per_day")
        result_autoanalyze_count_per_day = executeSQL(conn, query_autoanalyze_count_per_day)
        logger_debug.debug("result_autoanalyze_count_per_day = " + str(result_autoanalyze_count_per_day[0][0]))

        logger_debug.debug("Executing result_total_DB_size_in_GB")
        result_total_DB_size_in_GB = executeSQL(conn, query_total_DB_size_in_GB)
        logger_debug.debug("result_total_DB_size_in_GB = " + str(result_total_DB_size_in_GB[0][0]))

        logger_debug.debug("Executing result_Active_replication_slot")
        result_Active_replication_slot = executeSQL(conn, query_Active_replication_slots)
        logger_debug.debug("result_Active_replication_slot = " + str(result_Active_replication_slot[0][0]))

        logger_debug.debug("Executing result_blocked_sessions")
        result_blocked_sessions = executeSQL(conn, query_blocked_sessions)
        logger_debug.debug("result_blocked_sessions = " + str(result_blocked_sessions[0][0]))

        logger_debug.debug("Executing result_wait_event")
        result_wait_event = executeSQL(conn, query_wait_event)
        json_result_wait_event={}
        for k in result_wait_event[0] :
            #logger.info(k)
            for d in k['array_to_json']:
                #logger.info(d)
                json_result_wait_event[d["wait_event"]]=d["count"]
                #logger.info(json_result_wait_event)
        logger_debug.debug( "result_wait_event= " + str(json_result_wait_event))

        logger_debug.debug("Executing result_table_stat")
        if len(schema_list) == 0:
            pass
        else:    
            result_table_stat = executeSQL(conn, query_table_stat)
            json_result_table_stat_autovacuum_count={}
            logger_debug.debug("starting result_table_stat_autovacuum_count")
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_autovacuum_count[d["Table_Name"]]=d["autovacuum_count"]
                    #logger.info(json_result_table_stat_autovacuum_count)
            logger_debug.debug( "result_table_stat_autovacuum_count= " + str(json_result_table_stat_autovacuum_count))        
            logger_debug.debug("starting result_table_stat_autoanalyze_count")
            json_result_table_stat_autoanalyze_count={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_autoanalyze_count[d["Table_Name"]]=d["autoanalyze_count"]
                    #logger.info(json_result_table_stat_autoanalyze_count)
            logger_debug.debug( "result_table_stat_autoanalyze_count= " + str(json_result_table_stat_autoanalyze_count))        
            json_result_table_stat_n_dead_tup={}
            logger_debug.debug("starting result_table_stat_n_dead_tup")
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_n_dead_tup[d["Table_Name"]]=d["n_dead_tup"]
                    #logger.info(json_result_table_stat_n_dead_tup)
            logger_debug.debug( "result_table_stat_n_dead_tup= " + str(json_result_table_stat_n_dead_tup))         
            logger_debug.debug("starting result_table_stat_n_live_tup")
            json_result_table_stat_n_live_tup={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_n_live_tup[d["Table_Name"]]=d["n_live_tup"]
                    #logger.info(json_result_table_stat_n_live_tup)
            logger_debug.debug( "result_table_stat_n_live_tup= " + str(json_result_table_stat_n_live_tup))
            logger_debug.debug("starting result_table_stat_dead_tup_percent")
            json_result_table_stat_dead_tup_percent={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_dead_tup_percent[d["Table_Name"]]=d["dead_tup_%"]
                    #logger.info(json_result_table_stat_dead_tup_percent)
            logger_debug.debug( "result_table_stat_dead_tup_percent= " + str(json_result_table_stat_dead_tup_percent))
            logger_debug.debug("starting result_table_stat_total_fts_scan")
            json_result_table_stat_total_fts_scan={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_total_fts_scan[d["Table_Name"]]=d["total_fts_scan"]
                    #logger.info(json_result_table_stat_total_fts_scan)
            logger_debug.debug( "result_table_stat_total_fts_scan= " + str(json_result_table_stat_total_fts_scan))
            logger_debug.debug("starting result_table_stat_total_idx_scan")
            json_result_table_stat_total_idx_scan={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_total_idx_scan[d["Table_Name"]]=d["total_idx_scan"]
                    #logger.info(json_result_table_stat_total_idx_scan)
            logger_debug.debug( "result_table_stat_total_idx_scan= " + str(json_result_table_stat_total_idx_scan))
            logger_debug.debug("starting result_table_stat_n_tup_ins")
            json_result_table_stat_n_tup_ins={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_n_tup_ins[d["Table_Name"]]=d["n_tup_ins"]
                    #logger.info(json_result_table_stat_n_tup_ins)
            logger_debug.debug( "result_table_stat_n_tup_ins= " + str(json_result_table_stat_n_tup_ins))
            logger_debug.debug("starting result_table_stat_n_tup_upd")
            json_result_table_stat_n_tup_upd={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_n_tup_upd[d["Table_Name"]]=d["n_tup_upd"]
                    #logger.info(json_result_table_stat_n_tup_upd)
            logger_debug.debug( "result_table_stat_n_tup_upd= " + str(json_result_table_stat_n_tup_upd))
            logger_debug.debug("starting result_table_stat_n_tup_del")
            json_result_table_stat_n_tup_del={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_n_tup_del[d["Table_Name"]]=d["n_tup_del"]
                    #logger.info(json_result_table_stat_n_tup_del)
            logger_debug.debug( "result_table_stat_n_tup_del= " + str(json_result_table_stat_n_tup_del))
            logger_debug.debug("starting result_table_stat_n_mod_since_analyze")
            json_result_table_stat_n_mod_since_analyze={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_n_mod_since_analyze[d["Table_Name"]]=d["n_mod_since_analyze"]
                    #logger.info(json_result_table_stat_n_mod_since_analyze)
            logger_debug.debug( "result_table_stat_n_mod_since_analyze= " + str(json_result_table_stat_n_mod_since_analyze))
            logger_debug.debug("starting result_table_stat_n_tup_hot_upd")
            json_result_table_stat_n_tup_hot_upd={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_n_tup_hot_upd[d["Table_Name"]]=d["n_tup_hot_upd"]
                    #logger.info(json_result_table_stat_n_tup_hot_upd)
            logger_debug.debug( "result_table_stat_n_tup_hot_upd= " + str(json_result_table_stat_n_tup_hot_upd))
            logger_debug.debug("starting result_table_stat_tup_ins_precent")
            json_result_table_stat_tup_ins_precent={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_tup_ins_precent[d["Table_Name"]]=d["tup_ins_%"]
                    #logger.info(json_result_table_stat_tup_ins_precent)
            logger_debug.debug( "result_table_stat_tup_ins_precent= " + str(json_result_table_stat_tup_ins_precent))
            logger_debug.debug("starting result_table_stat_tup_upd_precent")
            json_result_table_stat_tup_upd_precent={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_tup_upd_precent[d["Table_Name"]]=d["tup_upd_%"]
                    #logger.info(json_result_table_stat_tup_upd_precent)
            logger_debug.debug( "result_table_stat_tup_upd_precent= " + str(json_result_table_stat_tup_upd_precent))
            logger_debug.debug("starting result_table_stat_tup_del_precent")
            json_result_table_stat_tup_del_precent={}
            for k in result_table_stat[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                    #logger.info(d)
                    json_result_table_stat_tup_del_precent[d["Table_Name"]]=d["tup_del_%"]
                    #logger.info(json_result_table_stat_tup_del_precent)
            logger_debug.debug( "result_table_stat_tup_del_precent= " + str(json_result_table_stat_tup_del_precent))

        logger_debug.debug("Executing result_oldest_open_transaction")
        result_oldest_open_transaction = executeSQL(conn, query_oldest_open_transaction)
        logger_debug.debug("result_oldest_open_transaction = " + str(result_oldest_open_transaction[0][0]))

        logger_debug.debug("Executing result_n_tables_eligible_for_autovacuum")
        result_n_tables_eligible_for_autovacuum = executeSQL(conn, query_n_tables_eligible_for_autovacuum)
        logger_debug.debug("result_n_tables_eligible_for_autovacuum = " + str(result_n_tables_eligible_for_autovacuum[0][0]))

        logger_debug.debug("Executing result_not_granted_lock")
        result_not_granted_lock  = executeSQL(conn, query_not_granted_lock)
        logger_debug.debug("result_not_granted_lock = " + str(result_not_granted_lock[0][0]))

        logger_debug.debug("Executing result_lock_mode")
        result_lock_mode = executeSQL(conn, query_lock_mode)
        json_result_lock_mode ={}
        for k in result_lock_mode[0] :
            #logger.info(k)
            for d in k['array_to_json']:
                #logger.info(d)
                json_result_lock_mode[d["lock_mode"]]=d["count"]
                #logger.info(json_result_lock_mode)
        logger_debug.debug( "result_lock_mode= " + str(json_result_lock_mode))
        
        logger_debug.debug("Executing result_lock_type")
        result_lock_type = executeSQL(conn, query_lock_type)
        json_result_lock_type ={}
        for k in result_lock_type[0] :
            #logger.info(k)
            for d in k['array_to_json']:
                #logger.info(d)
                json_result_lock_type[d["lock_type"]]=d["count"]
                #logger.info(json_result_lock_type)
        logger_debug.debug( "result_lock_type= " + str(json_result_lock_type))

        logger_debug.debug("Executing result_xact_commit")
        result_xact_commit = executeSQL(conn, query_xact_commit)
        logger_debug.debug("result_xact_commit = " + str(result_xact_commit[0][0]))

        logger_debug.debug("Executing result_xact_rollback")
        result_xact_rollback = executeSQL(conn, query_xact_rollback)
        logger_debug.debug("result_xact_rollback = " + str(result_xact_rollback[0][0]))

        logger_debug.debug("Executing result_xact_commit_ratio")
        result_xact_commit_ratio = executeSQL(conn, query_xact_commit_ratio)
        logger_debug.debug("result_xact_commit_ratio= " + str(result_xact_commit_ratio[0][0]))

        logger_debug.debug("Executing result_tup_returned")
        result_tup_returned = executeSQL(conn, query_tup_returned)
        logger_debug.debug("result_tup_returned = " + str(result_tup_returned[0][0]))

        logger_debug.debug("Executing result_tup_fetched")
        result_tup_fetched = executeSQL(conn, query_tup_fetched)
        logger_debug.debug("result_tup_fetched = " + str(result_tup_fetched[0][0]))

        logger_debug.debug("Executing result_tup_updated")
        result_tup_updated = executeSQL(conn, query_tup_updated)
        logger_debug.debug("result_tup_updated = " + str(result_tup_updated[0][0]))

        logger_debug.debug("Executing result_tup_deleted")
        result_tup_deleted = executeSQL(conn, query_tup_deleted)
        logger_debug.debug("result_tup_deleted = " + str(result_tup_deleted[0][0]))

        logger_debug.debug("Executing result_tup_inserted")
        result_tup_inserted = executeSQL(conn, query_tup_inserted)
        logger_debug.debug("result_tup_inserted = " + str(result_tup_inserted[0][0]))

        logger_debug.debug("Executing result_checkpoints_requested")
        result_checkpoints_requested = executeSQL(conn, query_checkpoints_requested)
        logger_debug.debug("result_checkpoints_requested = " + str(result_checkpoints_requested[0][0]))

        logger_debug.debug("Executing result_checkpoints_timed")
        result_checkpoints_timed = executeSQL(conn, query_checkpoints_timed)
        logger_debug.debug("result_checkpoints_timed = " + str(result_checkpoints_timed[0][0]))
   
        logger_debug.debug("Executing result_Oldest_Replication_Slot_Lag_gb_behind")
        result_Oldest_Replication_Slot_Lag_gb_behind = executeSQL(conn, query_Oldest_Replication_Slot_Lag_gb_behind)
        logger_debug.debug("result_Oldest_Replication_Slot_Lag_gb_behind = " + str(result_Oldest_Replication_Slot_Lag_gb_behind[0][0]))

        logger_debug.debug("Executing result_oldest_open_idl_in_transaction")
        result_oldest_open_idl_in_transaction = executeSQL(conn, query_oldest_open_idl_in_transaction)
        logger_debug.debug("result_oldest_open_idl_in_transaction = " + str(result_oldest_open_idl_in_transaction[0][0]))

        logger_debug.debug("Executing result_count_replication_slots")
        result_count_replication_slots = executeSQL(conn, query_count_replication_slots)
        logger_debug.debug("result_count_replication_slots = " + str(result_count_replication_slots[0][0]))
 
        logger_debug.debug("Executing result_Oldest_Replication_Slot_Lag_gb_behind_per_slot")
        result_Oldest_Replication_Slot_Lag_gb_behind_per_slot = executeSQL(conn, query_Oldest_Replication_Slot_Lag_gb_behind_per_slot)
        if result_count_replication_slots[0][0] > 0: 
           json_result_Oldest_Replication_Slot_Lag_gb_behind_per_slot={}
           for k in result_Oldest_Replication_Slot_Lag_gb_behind_per_slot[0] :
                #logger.info(k)
                for d in k['array_to_json']:
                   #logger.info(d)
                   json_result_Oldest_Replication_Slot_Lag_gb_behind_per_slot[d["slot_name"]]=d["oldest_replication_slot_lag_gb_behind"]
           logger_debug.debug("json_result_Oldest_Replication_Slot_Lag_gb_behind_per_slot = " + str(json_result_Oldest_Replication_Slot_Lag_gb_behind_per_slot))
        else:
            logger_debug.debug("---------> there is no Replication Slots in the Database")
            pass

        logger_debug.debug("Executing result_pg_stat_statements_extension")
        result_pg_stat_statements_extension = executeSQL(conn, query_pg_stat_statements_extension)
        logger_debug.debug("result_pg_stat_statements_extension = " + str(result_pg_stat_statements_extension[0][0]))
        
        logger_debug.debug("Executing result_pg_stat_statements")
        if result_pg_stat_statements_extension[0][0] == 0:
            logger_debug.debug("---------> pg_stat_statements extension is not enabled")
            pass
        else:
            logger_debug.debug("---------> pg_stat_statements extension is enabled")
            result_pg_stat_statements = executeSQL(conn, query_pg_stat_statements)
            json_result_pg_stat_statements_calls={}
            logger_debug.debug("starting result_pg_stat_statements_calls")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_calls[d["queryid"]]=d["calls"]
            logger_debug.debug( "json_result_pg_stat_statements_calls= " + str(json_result_pg_stat_statements_calls))     
            json_result_pg_stat_statements_total_time_msec={}
            logger_debug.debug("starting result_pg_stat_statements_total_time_msec")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_total_time_msec[d["queryid"]]=d["total_time_msec"]
            logger_debug.debug( "json_result_pg_stat_statements_total_time_msec= " + str(json_result_pg_stat_statements_total_time_msec))
            json_result_pg_stat_statements_min_time_msec={}
            logger_debug.debug("starting result_pg_stat_statements_min_time_msec")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_min_time_msec[d["queryid"]]=d["min_time_msec"]
            logger_debug.debug( "json_result_pg_stat_statements_min_time_msec= " + str(json_result_pg_stat_statements_min_time_msec))
            json_result_pg_stat_statements_max_time_msec={}
            logger_debug.debug("starting result_pg_stat_statements_max_time_msec")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_max_time_msec[d["queryid"]]=d["max_time_msec"]
            logger_debug.debug( "json_result_pg_stat_statements_max_time_msec= " + str(json_result_pg_stat_statements_max_time_msec))
            json_result_pg_stat_statements_avg_time_msec={}
            logger_debug.debug("starting result_pg_stat_statements_avg_time_msec")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_avg_time_msec[d["queryid"]]=d["avg_time_msec"]
            logger_debug.debug( "json_result_pg_stat_statements_avg_time_msec= " + str(json_result_pg_stat_statements_avg_time_msec))
            json_result_pg_stat_statements_stddev_time_msec={}
            logger_debug.debug("starting result_pg_stat_statements_stddev_time_msec")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_stddev_time_msec[d["queryid"]]=d["stddev_time_msec"]
            logger_debug.debug( "json_result_pg_stat_statements_stddev_time_msec= " + str(json_result_pg_stat_statements_stddev_time_msec))
            json_result_pg_stat_statements_rows_per_exec={}
            logger_debug.debug("starting result_pg_stat_statements_rows_per_exec")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_rows_per_exec[d["queryid"]]=d["rows_per_exec"]
            logger_debug.debug( "json_result_pg_stat_statements_rows_per_exec= " + str(json_result_pg_stat_statements_rows_per_exec))
            json_result_pg_stat_statements_rows={}
            logger_debug.debug("starting result_pg_stat_statements_rows")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_rows[d["queryid"]]=d["rows"]
            logger_debug.debug( "json_result_pg_stat_statements_rows= " + str(json_result_pg_stat_statements_rows))
            json_result_pg_stat_statements_db_time_percent={}
            logger_debug.debug("starting result_pg_stat_statements_db_time_percent")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_db_time_percent[d["queryid"]]=d["db_time_percent"]
            logger_debug.debug( "json_result_pg_stat_statements_db_time_percent= " + str(json_result_pg_stat_statements_db_time_percent))
            json_result_pg_stat_statements_shared_blks_hit={}
            logger_debug.debug("starting result_pg_stat_statements_shared_blks_hit")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_shared_blks_hit[d["queryid"]]=d["shared_blks_hit"]
            logger_debug.debug( "json_result_pg_stat_statements_shared_blks_hit= " + str(json_result_pg_stat_statements_shared_blks_hit))
            json_result_pg_stat_statements_shared_blks_read={}
            logger_debug.debug("starting result_pg_stat_statements_shared_blks_read")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_shared_blks_read[d["queryid"]]=d["shared_blks_read"]
            logger_debug.debug( "json_result_pg_stat_statements_shared_blks_read= " + str(json_result_pg_stat_statements_shared_blks_read))
            json_result_pg_stat_statements_shared_blks_dirtied={}
            logger_debug.debug("starting result_pg_stat_statements_shared_blks_dirtied")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_shared_blks_dirtied[d["queryid"]]=d["shared_blks_dirtied"]
            logger_debug.debug( "json_result_pg_stat_statements_shared_blks_dirtied= " + str(json_result_pg_stat_statements_shared_blks_dirtied))
            json_result_pg_stat_statements_shared_blks_written={}
            logger_debug.debug("starting result_pg_stat_statements_shared_blks_written")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_shared_blks_written[d["queryid"]]=d["shared_blks_written"]
            logger_debug.debug( "json_result_pg_stat_statements_shared_blks_written= " + str(json_result_pg_stat_statements_shared_blks_written))
            json_result_pg_stat_statements_local_blks_hit={}
            logger_debug.debug("starting result_pg_stat_statements_local_blks_hit")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_local_blks_hit[d["queryid"]]=d["local_blks_hit"]
            logger_debug.debug( "json_result_pg_stat_statements_local_blks_hit= " + str(json_result_pg_stat_statements_local_blks_hit))
            json_result_pg_stat_statements_local_blks_read={}
            logger_debug.debug("starting result_pg_stat_statements_local_blks_read")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_local_blks_read[d["queryid"]]=d["local_blks_read"]
            logger_debug.debug( "json_result_pg_stat_statements_local_blks_read= " + str(json_result_pg_stat_statements_local_blks_read))
            json_result_pg_stat_statements_local_blks_dirtied={}
            logger_debug.debug("starting result_pg_stat_statements_local_blks_dirtied")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_local_blks_dirtied[d["queryid"]]=d["local_blks_dirtied"]
            logger_debug.debug( "json_result_pg_stat_statements_local_blks_dirtied= " + str(json_result_pg_stat_statements_local_blks_dirtied))
            json_result_pg_stat_statements_local_blks_written={}
            logger_debug.debug("starting result_pg_stat_statements_local_blks_written")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_local_blks_written[d["queryid"]]=d["local_blks_written"]
            logger_debug.debug( "json_result_pg_stat_statements_local_blks_written= " + str(json_result_pg_stat_statements_local_blks_written))
            json_result_pg_stat_statements_temp_blks_read={}
            logger_debug.debug("starting result_pg_stat_statements_temp_blks_read")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_temp_blks_read[d["queryid"]]=d["temp_blks_read"]
            logger_debug.debug( "json_result_pg_stat_statements_temp_blks_read= " + str(json_result_pg_stat_statements_temp_blks_read))
            json_result_pg_stat_statements_temp_blks_written={}
            logger_debug.debug("starting result_pg_stat_statements_temp_blks_written")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_temp_blks_written[d["queryid"]]=d["temp_blks_written"]
            logger_debug.debug( "json_result_pg_stat_statements_temp_blks_written= " + str(json_result_pg_stat_statements_temp_blks_written))
            json_result_pg_stat_statements_blk_read_time_msec={}
            logger_debug.debug("starting result_pg_stat_statements_blk_read_time_msec")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_blk_read_time_msec[d["queryid"]]=d["blk_read_time_msec"]
            logger_debug.debug( "json_result_pg_stat_statements_blk_read_time_msec= " + str(json_result_pg_stat_statements_blk_read_time_msec))
            json_result_pg_stat_statements_blk_write_time_msec={}
            logger_debug.debug("starting result_pg_stat_statements_blk_write_time_msec")
            for k in result_pg_stat_statements[0] :
                for d in k['array_to_json']:
                    json_result_pg_stat_statements_blk_write_time_msec[d["queryid"]]=d["blk_write_time_msec"]
            logger_debug.debug( "json_result_pg_stat_statements_blk_write_time_msec= " + str(json_result_pg_stat_statements_blk_write_time_msec))
        logger_debug.debug("Executing result_db_load_cpu")
        result_db_load_cpu = executeSQL(conn, query_db_load_cpu)
        logger_debug.debug("result_db_load_cpu = " + str(result_db_load_cpu[0][0]))

        logger_debug.debug("Executing result_db_load_none_cpu")
        result_db_load_none_cpu = executeSQL(conn, query_db_load_none_cpu)
        logger_debug.debug("result_db_load_none_cpu = " + str(result_db_load_none_cpu[0][0]))

        logger_debug.debug("Executing result_bgwriter_buffers_clean")
        result_bgwriter_buffers_clean = executeSQL(conn, query_bgwriter_buffers_clean)
        logger_debug.debug("result_bgwriter_buffers_clean = " + str(result_bgwriter_buffers_clean[0][0]))

        logger_debug.debug("Executing result_bgwriter_buffers_backend")
        result_bgwriter_buffers_backend = executeSQL(conn, query_bgwriter_buffers_backend)
        logger_debug.debug("result_bgwriter_buffers_backend = " + str(result_bgwriter_buffers_backend[0][0]))

        logger_debug.debug("Executing result_bgwriter_maxwritten_clean")
        result_bgwriter_maxwritten_clean = executeSQL(conn, query_bgwriter_maxwritten_clean)
        logger_debug.debug("result_bgwriter_maxwritten_clean = " + str(result_bgwriter_maxwritten_clean[0][0]))

        logger_debug.debug("Executing result_oldest_mxid")
        result_oldest_mxid = executeSQL(conn, query_oldest_mxid)
        logger_debug.debug("result_oldest_mxid = " + str(result_oldest_mxid[0][0]))

        logger_debug.debug("Executing result_autovacuum_multixact_freeze_max_age")
        result_autovacuum_multixact_freeze_max_age = executeSQL(conn, query_autovacuum_multixact_freeze_max_age)
        logger_debug.debug("result_autovacuum_multixact_freeze_max_age = " + str(result_autovacuum_multixact_freeze_max_age[0][0]))

        logger.info("------------------------------")
        logger.info("the queries execution finished")
        logger.info("------------------------------")
        # Create CloudWatch client
        logger.info("-------------------------------------")
        logger.info("starting  cloudwatch.put_metric_data")
        logger.info("-------------------------------------")
        cloudwatch = boto3.client('cloudwatch')
        # Put Counter custom metrics
        logger_debug.debug("starting  cloudwatch.put_metric_data.result_percent_towards_wraparound")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'Xid_Percent_Towards_Wraparound',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Percent',
                    'Value': result_percent_towards_wraparound[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.queries_canceled_due_to_lock_timeout")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'queries_canceled_due_to_lock_timeouts',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_queries_canceled_due_to_lock_timeouts[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.queries_canceled_due_to_lock_deadlocks")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'queries_canceled_due_to_lock_deadlocks',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_queries_canceled_due_to_lock_deadlocks[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.idle_in_transaction_sessions")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'idle_in_transaction_sessions',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_idle_in_transaction_sessions[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.idle_sessions")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'idle_sessions',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_idle_sessions[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.idle_in_transaction_aborted_sessions")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'idle_in_transaction_aborted_sessions',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_idle_in_transaction_aborted_sessions[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.active_sessions")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'active_sessions',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_active_sessions[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.Inactive_replication_slot")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'Inactive_replication_slot',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_Inactive_replication_slot[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.invalid_indexes")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'invalid_indexes',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_invalid_indexes[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.deadlocks")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'deadlocks',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_deadlocks[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.total_connections")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'total_connections',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_total_connections[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.max_connections")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'max_connections',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_max_connections[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.connections_utilization")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'connections_utilization',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Percent',
                    'Value': result_connections_utilization
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.autovacuum_freeze_max_age")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'autovacuum_freeze_max_age',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_autovacuum_freeze_max_age[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.oldest_xid")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'oldest_xid',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_oldest_xid[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.percent_towards_emergency_autovacuum")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'percent_towards_emergency_autovacuum',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Percent',
                    'Value': result_percent_towards_emergency_autovacuum
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.autovacuum_count_per_min")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'autovacuum_count_per_min',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_autovacuum_count_per_min[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.autovacuum_count_per_hour")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'autovacuum_count_per_hour',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_autovacuum_count_per_hour[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.autovacuum_count_per_day")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'autovacuum_count_per_day',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_autovacuum_count_per_day[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.autoanalyze_count_per_min")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'autoanalyze_count_per_min',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_autoanalyze_count_per_min[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.autoanalyze_count_per_hour")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'autoanalyze_count_per_hour',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_autoanalyze_count_per_hour[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.autoanalyze_count_per_day")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'autoanalyze_count_per_day',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_autoanalyze_count_per_day[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.total_DB_size_in_GB")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'total_DB_size_in_GB',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Gigabits',
                    'Value': result_total_DB_size_in_GB[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.Active_replication_slot")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'Active_replication_slot',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_Active_replication_slot[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.blocked_sessions")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'blocked_sessions',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_blocked_sessions[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.wait_event")
        for k in json_result_wait_event:
            wait_event=k
            wait_event_sample=json_result_wait_event[k]
            #logger.info(wait_event)
            cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': "wait_event_"+wait_event ,
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': wait_event_sample
                },
            ],
            Namespace='PG Counter Metrics'
        )
        if len(schema_list) == 0:
            pass
        else:    
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_autovacuum_count")
            for k in json_result_table_stat_autovacuum_count:
                Table_Name=k
                autovacuum_count=json_result_table_stat_autovacuum_count[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_autovacuum_count_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': autovacuum_count
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_autoanalyze_count")
            for k in json_result_table_stat_autoanalyze_count:
                Table_Name=k
                autoanalyze_count=json_result_table_stat_autoanalyze_count[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_autoanalyze_count_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': autoanalyze_count
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_n_dead_tup")
            for k in json_result_table_stat_n_dead_tup:
                Table_Name=k
                n_dead_tup=json_result_table_stat_n_dead_tup[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_n_dead_tup_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': n_dead_tup
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_n_live_tup")
            for k in json_result_table_stat_n_live_tup:
                Table_Name=k
                n_live_tup=json_result_table_stat_n_live_tup[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_n_live_tup_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': n_live_tup
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_dead_tup_percent")
            for k in json_result_table_stat_dead_tup_percent:
                Table_Name=k
                dead_tup_percent=json_result_table_stat_dead_tup_percent[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_dead_tup_percent_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Percent',
                        'Value': dead_tup_percent
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_total_fts_scan")
            for k in json_result_table_stat_total_fts_scan:
                Table_Name=k
                total_fts_scan=json_result_table_stat_total_fts_scan[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_total_fts_scan_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': total_fts_scan
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_total_idx_scan")
            for k in json_result_table_stat_total_idx_scan:
                Table_Name=k
                total_idx_scan=json_result_table_stat_total_idx_scan[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_total_idx_scan_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': total_idx_scan
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_n_tup_ins")
            for k in json_result_table_stat_n_tup_ins:
                Table_Name=k
                n_tup_ins=json_result_table_stat_n_tup_ins[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_n_tup_ins_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': n_tup_ins
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_n_tup_upd")
            for k in json_result_table_stat_n_tup_upd:
                Table_Name=k
                n_tup_upd=json_result_table_stat_n_tup_upd[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_n_tup_upd_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': n_tup_upd
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_n_tup_del")
            for k in json_result_table_stat_n_tup_del:
                Table_Name=k
                n_tup_del=json_result_table_stat_n_tup_del[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_n_tup_del_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': n_tup_del
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_n_mod_since_analyze")
            for k in json_result_table_stat_n_mod_since_analyze:
                Table_Name=k
                n_mod_since_analyze=json_result_table_stat_n_mod_since_analyze[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_n_mod_since_analyze_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': n_mod_since_analyze
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_n_tup_hot_upd")
            for k in json_result_table_stat_n_tup_hot_upd:
                Table_Name=k
                n_tup_hot_upd=json_result_table_stat_n_tup_hot_upd[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_n_tup_hot_upd_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': n_tup_hot_upd
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_tup_ins_precent")
            for k in json_result_table_stat_tup_ins_precent:
                Table_Name=k
                tup_ins_precent=json_result_table_stat_tup_ins_precent[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_tup_ins_precent_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Percent',
                        'Value': tup_ins_precent
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_tup_upd_precent")
            for k in json_result_table_stat_tup_upd_precent:
                Table_Name=k
                tup_upd_precent=json_result_table_stat_tup_upd_precent[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_tup_upd_precent_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Percent',
                        'Value': tup_upd_precent
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.table_stat_tup_del_precent")
            for k in json_result_table_stat_tup_del_precent:
                Table_Name=k
                tup_del_precent=json_result_table_stat_tup_del_precent[k]
                #logger.info(Table_Name)
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "table_stat_tup_del_precent_"+Table_Name ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Percent',
                        'Value': tup_del_precent
                    },
                ],
                Namespace='PG Counter Metrics'
            )
        logger_debug.debug("starting  cloudwatch.put_metric_data.oldest_open_transaction")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'oldest_open_transaction',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Seconds',
                    'Value': result_oldest_open_transaction[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.n_tables_eligible_for_autovacuum")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'n_tables_eligible_for_autovacuum',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_n_tables_eligible_for_autovacuum[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.not_granted_lock")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'not_granted_lock',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_not_granted_lock[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.lock_mode")
        for k in json_result_lock_mode:
            lock_mode=k
            lock_mode_sample=json_result_lock_mode[k]
            #logger.info(lock_mode)
            cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': "lock_mode_"+lock_mode ,
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': lock_mode_sample
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.lock_type")
        for k in json_result_lock_type:
            lock_type=k
            lock_type_sample=json_result_lock_type[k]
            #logger.info(lock_type)
            cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': "lock_type_"+lock_type ,
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': lock_type_sample
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.xact_commit")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'xact_commit',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_xact_commit[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.xact_rollback")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'xact_rollback',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_xact_rollback[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.xact_commit_ratio")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'xact_commit_ratio',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Percent',
                    'Value': result_xact_commit_ratio[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.tup_returned")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'tup_returned',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_tup_returned[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.tup_fetched")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'tup_fetched',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_tup_fetched[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.tup_deleted")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'tup_deleted',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_tup_deleted[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.tup_updated")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'tup_updated',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_tup_updated[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.tup_inserted")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'tup_inserted',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_tup_inserted[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.checkpoints_requested")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'checkpoints_requested',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_checkpoints_requested[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.checkpoints_timed")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'checkpoints_timed',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_checkpoints_timed[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.Oldest_Replication_Slot_Lag_gb_behind")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'Oldest_Replication_Slot_Lag_gb_behind',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Gigabits',
                    'Value': result_Oldest_Replication_Slot_Lag_gb_behind[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.oldest_open_idl_in_transaction")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'oldest_open_idl_in_transaction',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Seconds',
                    'Value': result_oldest_open_idl_in_transaction[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.Oldest_Replication_Slot_Lag_gb_behind_per_slot")
        if result_count_replication_slots[0][0] > 0:
            for k in json_result_Oldest_Replication_Slot_Lag_gb_behind_per_slot:
                slot_name=k
                oldest_replication_slot_lag_gb_behind=json_result_Oldest_Replication_Slot_Lag_gb_behind_per_slot[k]
                cloudwatch.put_metric_data(
                    MetricData=[
                        {
                           'MetricName': "Oldest_Replication_Slot_Lag_gb_behind_"+slot_name ,
                            'Dimensions': [
                                {
                                    'Name': 'DBInstanceIdentifier',
                                    'Value': rds_config.metric_name
                                },
                           ],
                            'Unit': 'Gigabits',
                            'Value': oldest_replication_slot_lag_gb_behind
                        },
                    ],
                    Namespace='PG Counter Metrics'
                )
        else:
            pass
        if result_pg_stat_statements_extension[0][0] == 0:
            logger_debug.debug("---------> pg_stat_statements extension is not enabled")
            pass
        else:
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_calls")
            for k in json_result_pg_stat_statements_calls:
                queryid=k
                calls=json_result_pg_stat_statements_calls[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_calls_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': calls
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_total_time_msec")
            for k in json_result_pg_stat_statements_total_time_msec:
                queryid=k
                total_time_msec=json_result_pg_stat_statements_total_time_msec[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_total_time_msec_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Milliseconds',
                        'Value': total_time_msec
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_min_time_msec")
            for k in json_result_pg_stat_statements_min_time_msec:
                queryid=k
                min_time_msec=json_result_pg_stat_statements_min_time_msec[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_min_time_msec_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Milliseconds',
                        'Value': min_time_msec
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_max_time_msec")
            for k in json_result_pg_stat_statements_max_time_msec:
                queryid=k
                max_time_msec=json_result_pg_stat_statements_max_time_msec[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_max_time_msec_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Milliseconds',
                        'Value': max_time_msec
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_avg_time_msec")
            for k in json_result_pg_stat_statements_avg_time_msec:
                queryid=k
                avg_time_msec=json_result_pg_stat_statements_avg_time_msec[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_avg_time_msec_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Milliseconds',
                        'Value': avg_time_msec
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_stddev_time_msec")
            for k in json_result_pg_stat_statements_stddev_time_msec:
                queryid=k
                stddev_time_msec=json_result_pg_stat_statements_stddev_time_msec[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_stddev_time_msec_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Milliseconds',
                        'Value': stddev_time_msec
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_rows_per_exec")
            for k in json_result_pg_stat_statements_rows_per_exec:
                queryid=k
                rows_per_exec=json_result_pg_stat_statements_rows_per_exec[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_rows_per_exec_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': rows_per_exec
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_rows")
            for k in json_result_pg_stat_statements_rows:
                queryid=k
                rows=json_result_pg_stat_statements_rows[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_rows_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': rows
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_db_time_percent")
            for k in json_result_pg_stat_statements_db_time_percent:
                queryid=k
                db_time_percent=json_result_pg_stat_statements_db_time_percent[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_db_time_percent_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Percent',
                        'Value': db_time_percent
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_shared_blks_hit")
            for k in json_result_pg_stat_statements_shared_blks_hit:
                queryid=k
                shared_blks_hit=json_result_pg_stat_statements_shared_blks_hit[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_shared_blks_hit_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': shared_blks_hit
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_shared_blks_read")
            for k in json_result_pg_stat_statements_shared_blks_read:
                queryid=k
                shared_blks_read=json_result_pg_stat_statements_shared_blks_read[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_shared_blks_read_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': shared_blks_read
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_shared_blks_dirtied")
            for k in json_result_pg_stat_statements_shared_blks_dirtied:
                queryid=k
                shared_blks_dirtied=json_result_pg_stat_statements_shared_blks_dirtied[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_shared_blks_dirtied_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': shared_blks_dirtied
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_shared_blks_written")
            for k in json_result_pg_stat_statements_shared_blks_written:
                queryid=k
                shared_blks_written=json_result_pg_stat_statements_shared_blks_written[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_shared_blks_written_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': shared_blks_written
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_local_blks_hit")
            for k in json_result_pg_stat_statements_local_blks_hit:
                queryid=k
                local_blks_hit=json_result_pg_stat_statements_local_blks_hit[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_local_blks_hit_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': local_blks_hit
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_local_blks_read")
            for k in json_result_pg_stat_statements_local_blks_read:
                queryid=k
                local_blks_read=json_result_pg_stat_statements_local_blks_read[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_local_blks_read_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': local_blks_read
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_local_blks_dirtied")
            for k in json_result_pg_stat_statements_local_blks_dirtied:
                queryid=k
                local_blks_dirtied=json_result_pg_stat_statements_local_blks_dirtied[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_local_blks_dirtied_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': local_blks_dirtied
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_local_blks_written")
            for k in json_result_pg_stat_statements_local_blks_written:
                queryid=k
                local_blks_written=json_result_pg_stat_statements_local_blks_written[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_local_blks_written_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': local_blks_written
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_temp_blks_read")
            for k in json_result_pg_stat_statements_temp_blks_read:
                queryid=k
                temp_blks_read=json_result_pg_stat_statements_temp_blks_read[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_temp_blks_read_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': temp_blks_read
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_temp_blks_written")
            for k in json_result_pg_stat_statements_temp_blks_written:
                queryid=k
                temp_blks_written=json_result_pg_stat_statements_temp_blks_written[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_temp_blks_written_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Count',
                        'Value': temp_blks_written
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_blk_read_time_msec")
            for k in json_result_pg_stat_statements_blk_read_time_msec:
                queryid=k
                blk_read_time_msec=json_result_pg_stat_statements_blk_read_time_msec[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_blk_read_time_msec_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Milliseconds',
                        'Value': blk_read_time_msec
                    },
                ],
                Namespace='PG Counter Metrics'
            )
            logger_debug.debug("starting  cloudwatch.put_metric_data.pg_stat_statements_blk_write_time_msec")
            for k in json_result_pg_stat_statements_blk_write_time_msec:
                queryid=k
                blk_write_time_msec=json_result_pg_stat_statements_blk_write_time_msec[k]
                cloudwatch.put_metric_data(
                MetricData=[
                    {
                        'MetricName': "pg_stat_statements_blk_write_time_msec_queryid_"+str(queryid) ,
                        'Dimensions': [
                            {
                                'Name': 'DBInstanceIdentifier',
                                'Value': rds_config.metric_name
                            },
                        ],
                        'Unit': 'Milliseconds',
                        'Value': blk_write_time_msec
                    },
                ],
                Namespace='PG Counter Metrics'
            )
        logger_debug.debug("starting  cloudwatch.put_metric_data.db_load_cpu")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'db_load_cpu',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_db_load_cpu[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.db_load_none_cpu")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'db_load_none_cpu',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_db_load_none_cpu[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.bgwriter_buffers_clean")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'bgwriter_buffers_clean',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_bgwriter_buffers_clean[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.bgwriter_buffers_backend")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'bgwriter_buffers_backend',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_bgwriter_buffers_backend[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.bgwriter_maxwritten_clean")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'bgwriter_maxwritten_clean',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_bgwriter_maxwritten_clean[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.oldest_mxid")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'oldest_mxid',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_oldest_mxid[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
        logger_debug.debug("starting  cloudwatch.put_metric_data.autovacuum_multixact_freeze_max_age")
        cloudwatch.put_metric_data(
            MetricData=[
                {
                    'MetricName': 'autovacuum_multixact_freeze_max_age',
                    'Dimensions': [
                        {
                            'Name': 'DBInstanceIdentifier',
                            'Value': rds_config.metric_name
                        },
                    ],
                    'Unit': 'Count',
                    'Value': result_autovacuum_multixact_freeze_max_age[0][0]
                },
            ],
            Namespace='PG Counter Metrics'
        )
    except (Exception) as error:
        logger.error(error)
        putErrorMetric()
        return None
    finally:
        if conn is not None:
            conn.close()
    logger.info("SUCCESS: PG Counter Metrics") 
    return "SUCCESS: PG Counter Metrics"
    
def executeSQL(connection, sqlString, bindHash={}, supress=False):
    """
    A wrapper for SQL execution, handling exceptions, and managing
    return values for non-select statements.
    The supress flag allows us to prevent chatty error logs for specific
    queries that we know may fail without us needing to worry about it.
    We still return False, though, so that we can detect the error.
    """
    isSelect = False
    if sqlString.upper().find("SELECT") == 0:
        isSelect = True
    success = True
    #statement_timeout in millisecond
    #It only applies to current session
    timeout = 10000;
    timeoutString = "SET statement_timeout = " + str(timeout)
    results = []
    try:
        cursor = connection.cursor()
        cursor.execute(timeoutString)
        cursor.execute(sqlString, bindHash)
        try: 
            if isSelect:
                results = cursor.fetchall()
        except:
            results = None
    except (Exception) as error:
        logger.error("ERROR: Unexpected error: Could not submit request: " + sqlString)
        logger.error("ERROR Message: " + str(error))
        success = False
    finally:
        connection.commit()
        cursor.close()
    if not success:
        return False
    elif isSelect:
        return results
    else:
        return None

def putErrorMetric():
    # Create CloudWatch client
    cloudwatch = boto3.client('cloudwatch')
    # Put custom metrics
    cloudwatch.put_metric_data(
        MetricData=[
            {
                'MetricName': 'PG_Counter_Metrics_Error_Count',
                'Dimensions': [
                    {
                        'Name': 'DBInstanceIdentifier',
                        'Value': rds_config.metric_name
                    },
                ],
                'Unit': 'None',
                'Value': 1
            },
        ],
        Namespace='PG Counter Metrics'
    )

def get_secret():
    logger.info("Secret name: " + secret_name)
    logger.info("Secret manager Region name: " + region)
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region
    )
    
    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.
    
    try:
        logger.info("start  get_secret_value_response ")
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        logger.info("Received get_secret_value_response ")
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            logger.info("Inside string response...")
            return get_secret_value_response['SecretString']
        else:
            logger.info("Inside binary response...")
            return base64.b64decode(get_secret_value_response['SecretBinary'])
