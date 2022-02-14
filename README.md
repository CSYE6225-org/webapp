# webapp

Prerequisites:

1. Python3
2. Djnago 3.2.7
3. Postgres
4. Bcrypt

How to setup?

1. Start postgres server with the following command: brew services start postgresql
2. Make the DB connection by running the following commands:
    python manage.py makemigrations
    python manage.py migrate
3. Run the dev server with python manage.py runserver

This app uses basic authentication so for getting user details and updating user details please use Basic auth. 

