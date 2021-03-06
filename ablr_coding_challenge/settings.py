"""
Django settings for ablr_coding_challenge project.

Generated by 'django-admin startproject' using Django 3.2.

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
SECRET_KEY = 'django-insecure-t4#ez(ebkd$yv$u5-w3osa@u#^4k-(q1oi68#%j%$48xcev3*1'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = [
  'django.contrib.auth',
  'django.contrib.contenttypes',
  'rest_framework',
  'corsheaders',
  'myinfo',
]

MIDDLEWARE = [
  'corsheaders.middleware.CorsMiddleware',
]

ROOT_URLCONF = 'ablr_coding_challenge.urls'

WSGI_APPLICATION = 'ablr_coding_challenge.wsgi.application'

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
  'default': {
    'ENGINE': 'django.db.backends.sqlite3',
    'NAME': BASE_DIR / 'db.sqlite3',
  }
}

# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
  'DEFAULT_RENDERER_CLASSES': (
    'rest_framework.renderers.JSONRenderer',
  )
}

CORS_ORIGIN_ALLOW_ALL = True
