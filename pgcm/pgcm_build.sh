#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#ver variable need to be changed with each new version 
ver=1.8


ZIP_FILE=pgcm_$ver.zip


# bin the old zipfile
if [ -f $ZIP_FILE ]; then
	echo " "
	echo "Removeing existing $ZIP_FILE file"
	rm -rf $ZIP_FILE
fi

cmd="zip -r $ZIP_FILE pgcm.py rds_config.py tables_config.py scramp/  pg8000/ certs/ asn1crypto/"
echo " "
echo $cmd
echo " "
eval $cmd
echo " "
echo "Generated new Lambda file $ZIP_FILE"
echo " "
chk="unzip -l $ZIP_FILE"
echo $chk
echo " "
eval $chk

