import os

#rds_config

# db_region
# AWS_REGION is Reserved environment variable for Lambda, The AWS Region where the Lambda function is executed. 
# if you want to use custom region replace AWS_REGION with REGION and add it as Lambda environment variable
db_region=os.getenv("AWS_REGION")
if db_region is None:
    raise Exception("Must Provide AWS REGION. Environment variable AWS_REGION")


# db_name   
db_name = os.getenv("DB_NAME") 
if db_name is None:
    raise Exception("Must Provide Database NAME. Environment variable DB_NAME")
    

#metric_name
metric_name = os.getenv("DB_INSATCNE_IDENTIFIER")+"_pgcm"
if metric_name is None:
    raise Exception("Must Provide Db Insatcne Identifier. Environment variable DB_INSATCNE_IDENTIFIER")


#rds_host
rds_host = os.getenv("RDS_ENDPOINT")
if rds_host is None:
    raise Exception("Must Provide RDS Endpoint. Environment variable RDS_ENDPOINT")
    

#db_port
db_port = os.getenv("DB_PORT")
if db_port is None:
    raise Exception("Must Provide DB PORT. Environment variable DB_PORT")

# db_username defaine the DB user name that will be used by PGCM to connect to the PG DB 
db_username = "user_pgcm"


# auth_type defaine the authentication Type 

auth_type_check =os.getenv("AUTHENTICATION_TYPE")
if auth_type_check is None:
    raise Exception("Must Provide Authentication_type [ iamdb or secret_manager or password ] . Environment variable AUTHENTICATION_TYPE")
else:
    if auth_type_check == 'password':
       auth_type = os.getenv("AUTHENTICATION_TYPE")
       username_password = os.getenv("PASSWORD")
       if username_password is None:
           raise Exception("Must Provide PASSWORD . Environment variable PASSWORD")
       db_secret_name ='N/A' 
    elif auth_type_check == 'secret_manager':
       auth_type = os.getenv("AUTHENTICATION_TYPE")
       db_secret_name = os.getenv("SECRET_NAME")
       if db_secret_name is None:
           raise Exception("Must Provide Secret Name . Environment variable SECRET_NAME")
       username_password ='N/A'       
    else:
        auth_type = os.getenv("AUTHENTICATION_TYPE")
        username_password ='N/A'
        db_secret_name ='N/A'


# RDS CA CERT
# for more info https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html
CA_CERT="certs/commercial/rds-ca-2019-root.pem"

