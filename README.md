# Innovative Instruments App Backend
> API’s create with Django Rest Framework

### Installation
```
# Clone this repository
$ git clone https://github.com/Unmesh28/backend.git

# Go into the repository
$ cd backend

# Create virtualenv
$ python -m venv env

# Activate virtualenv
$ source env/Scripts/activate (For Windows)
$ source env/bin/activate (For Mac)

# Install packages
$ pip install -r requirements.txt

# Create a database
# Copy the contents of .env.example to .env and
  modify .env as necessary

# Migrate the database
$ python manage.py migrate

# Create new user
$ python manage.py createsuperuser

# Run the project
$ python manage.py runserver
```
