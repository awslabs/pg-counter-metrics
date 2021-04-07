import os
#tables_config
#Examples of the tables configuration in environment variables
#SCHEMA_LIST = ('schema_1','schema_2')
#TABLES_LIST = ('table_1','table_2')
#
#SCHEMA_LIST = ('schema_1')
#TABLES_LIST = ('table_1','table_2','table_3')
 
schema_list = os.getenv("SCHEMA_LIST")
tables_list = os.getenv("TABLES_LIST")
