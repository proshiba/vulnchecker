import os
from logging import getLogger, config as logconf

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
LOG_CONF = CONF_DIR+"/log.conf"
logconf.fileConfig(LOG_CONF)

import main

def lambda_handler(event, context):
    try:
        main.main()
        return {
            'statusCode': 200,
            'body': "success"
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': str(e)
        }