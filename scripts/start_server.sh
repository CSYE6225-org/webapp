#!/bin/bash
cd /home/ubuntu/webapp/todo
python3 manage.py migrate
python3 manage.py runserver 0.0.0.0:8000 > /dev/null 2> /dev/null < /dev/null &