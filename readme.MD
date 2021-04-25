# ablr Demo App
This is the backend of a demo application that retrieves user's personal data from the Singpass MyInfo API.

## Prerequisite
This is a Django application that runs with python3.6 or above. 
Install the latest python from https://www.python.org/downloads/.

Before running the tests or application, set up a venv by following https://docs.python.org/3/library/venv.html 
and install the dependencies using pip:
```shell script
# Set up venv
python3 -m venv myvenv
source myvenv/bin/activate 
# Install dependencies
pip install -r requirements.txt
```

## Setting up the environment
Various settings related to Singpass and MyInfo can be adjusted in `myinfo/settings.py`.

## Running the tests
Run the tests in the root project directory:
```shell script
python manage.py test 
```

## Running the application
Run the application in the root project directory:
```shell script
python manage.py runserver 8000
```
The application should now be running on `localhost:8000`.
