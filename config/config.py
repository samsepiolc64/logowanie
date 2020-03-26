import os #.env

DEBUG = True

SECRET_KEY = os.environ.get('SECRET_KEY')
SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:pg@localhost/waterapp'
SQLALCHEMY_TRACK_MODIFICATIONS = False