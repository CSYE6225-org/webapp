"""
Django settings for todo project.

Generated by 'django-admin startproject' using Django 3.2.7.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""

import os
from pathlib import Path
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent



# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-rg7fzv(&0w@!0*#ixv9u7&%8_wr(2u*e15+6r51y+r3-tke91$'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False


ALLOWED_HOSTS = ['127.0.0.1', 'dev.maneesh.me', 'prod.maneesh.me']




# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'todoapp',
    'rest_framework',
    'user'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'todo.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'todo.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

if os.environ.get('USER') == 'maneeshsakthivel':
    DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'TodoDB',
        'USER': 'newuser',
        'PASSWORD': 'postgres',
        'HOST': 'localhost'  
        }
    }
    
elif os.environ.get('GITHUB_WORKFLOW'):
    DATABASES = {
        'default': {
           'ENGINE': 'django.db.backends.postgresql',
           'NAME': 'github_actions',
           'USER': 'postgres',
           'PASSWORD': 'postgres',
           'HOST': '127.0.0.1',
           'PORT': '5432',
        }
    }
else:
    import json
    overrides = json.loads(open('/home/ubuntu/server/config.json').read())
    print(overrides)    
    S3_BUCKET_NAME = overrides.get('s3')
    DATABASES = {
        'default': {
                'ENGINE': 'django.db.backends.postgresql_psycopg2',
                'NAME': overrides.get('database'),
                'USER': overrides.get('username'),
                'PASSWORD': overrides.get('password'),
                'HOST': overrides.get('host').split(':')[0],
                'PORT': overrides.get('host').split(':')[1],
        }
    }


# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

from boto3.session import Session
# ...
CLOUDWATCH_AWS_ID = "AKIAZ7SWXZPJKXRK2VUL"
CLOUDWATCH_AWS_KEY = "hKPH/Kbd/eucG7CMXaddRdZDp0IDU1qVtYnZ8dOy"
AWS_DEFAULT_REGION = 'us-east-1' # Be sure to update with your AWS region
logger_boto3_session = Session(
    aws_access_key_id=CLOUDWATCH_AWS_ID,
    aws_secret_access_key=CLOUDWATCH_AWS_KEY,
    region_name=AWS_DEFAULT_REGION,
)


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "aws": {
            "format": "%(asctime)s [%(levelname)-8s] %(message)s [%(pathname)s:%(lineno)d]",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "watchtower": {
            "level": "INFO",
            "class": "watchtower.CloudWatchLogHandler",
            # From step 2
            "boto3_session": logger_boto3_session,
            "log_group": "DemoLogs",
            # Different stream for each environment
            "stream_name": f"logs",
            "formatter": "aws",
        },
        "console": {"class": "logging.StreamHandler", "formatter": "aws",},
    },
    "loggers": {
        # Use this logger to send data just to Cloudwatch
        "watchtower": {"level": "INFO", "handlers": ["watchtower"], "propogate": False,}
    },
}

# LOGGING = {
#     'version': 1,
#     # Version of logging
#     'disable_existing_loggers': False,
 
#     'filters':{
#         #information regarding filters
#     },
 
#     'formatters':{
#         'Simple_Format':{
#             'format': '{levelname} {message}',
#             'style': '{',
#         }
#     },
 
#     'handlers': {
#         'file': {
#             'level': 'DEBUG',
#             'class': 'logging.FileHandler',
#             'formatter': 'Simple_Format',
#             'filename': './logs/log_file.log'
#         },
 
#         'console': {
#             'level': 'DEBUG',
#             'class': 'logging.StreamHandler',
#         },
#     },
 
#     'loggers': {
#         'django': {
#             'handlers': ['file', 'console'],
#             'level': 'DEBUG',
#         },
#     },
# }


# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
REST_FRAMEWORK = {
    # other settings...

    'DEFAULT_AUTHENTICATION_CLASSES': [],
    'DEFAULT_PERMISSION_CLASSES': [],
}

import os
STATIC_ROOT = os.path.join(BASE_DIR, "static/")

AWS_ACCESS_KEY_ID = "AKIA4FDOUDW65OSZKSOE"
AWS_SECRET_ACCESS_KEY = "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"
