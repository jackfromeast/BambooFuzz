# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_migrate import Migrate
from os import environ
from sys import exit
from decouple import config
import logging

from config import config_dict
from app import create_app, db

from flask_uploads import UploadSet, configure_uploads, ARCHIVES, patch_request_class

# WARNING: Don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

# The configuration
get_config_mode = 'Debug' if DEBUG else 'Production'

try:
    
    # Load the configuration using the default values 
    app_config = config_dict[get_config_mode.capitalize()]

except KeyError:
    exit('Error: Invalid <config_mode>. Expected values [Debug, Production] ')

app = create_app( app_config ) 
Migrate(app, db)
# # 上传文件的配置
# app.config['SECRET_KEY'] = 'I have a dream'
app.config['UPLOADED_FIRMWARE_DEST'] = "Web/upload_firmwares"  #os.getcwd上传文件存放的位置
archives=list(ARCHIVES)
archives.append("bin")
archives.append("")
firmware = UploadSet('firmware', ARCHIVES)
configure_uploads(app, firmware)
patch_request_class(app,50 * 1024 * 1024)  # set maximum file size, default is 16MB

if DEBUG:
    app.logger.info('DEBUG       = ' + str(DEBUG)      )
    app.logger.info('Environment = ' + get_config_mode )
    app.logger.info('DBMS        = ' + app_config.SQLALCHEMY_DATABASE_URI )

if __name__ == "__main__":
    app.run(host="0.0.0.0")
