# Changelog

# V1.4            

```                                                    
1. change the oldest_open_transaction metric to be for the active session only   

2. add new metrics  1-oldest_open_idl_in_transaction                             

                    2-Oldest_Replication_Slot_Lag_gb_behind_per_slot             

                    3-Oldest_Replication_Slot_Lag_gb_behind
```

# V1.5  
                                                              
```
1. Enhance the logging and add the debug mode                                    

2. Add tables_config.py to enhance the tables metric configuration               
```

# V1.6   

```                                                            
1. Add support to aws secret manager and clear password authentication          

2. Add new metrics 1-db_load_cpu  2-db_load_none_cpu                             

3. Add new 3 metrics for bgwriter
  ( buffers_clean , buffers_backend ,maxwritten_clean)  
```

# V1.7                                                                

```
1. Add 2 metrics for MXID (Multixacts).     
```

# V1.8                             

```
1. upgrade pg8000 from 1.12.5 to 1.18.0 to fix ssl bug , the new version need    

   two py pkgs scramp and asn1crypto to support scram auth                       

3. use Lambda environment variables to adjust PGCM configuration without updating code and to support cloudformation deployment  

```   

# V1.9                             

```
1. Add the RDS certificate bundle that contains both the intermediate and root certificates for all AWS Region 
   (https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions)

2. Fix "errorMessage": "name 'metric_dimension_name' is not defined"  by replacing metric_dimension_name with metric_name .

3. Rename Oldest_Replication_Slot_Lag_gb_behind to Oldest_Replication_Slot_Lag .

4. Rename Oldest_Replication_Slot_Lag_gb_behind_per_slot_(slot_name) to Replication_Slot_Lag_(slot_name) ;

5. Change the unites of both Oldest_Replication_Slot_Lag and Replication_Slot_Lag_(slot_name) to be bytes instead of GB .

6. Fix the user name in create_database_user_pwd_pgcm.sql .


```                     