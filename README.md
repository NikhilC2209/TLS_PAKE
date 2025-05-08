# TLS with PAKE

### **SETUP**

Create a python venv named localenv

`python3 -m venv localenv`

Enter your python venv using `source ./env` (I've included a bash script `env` which you can use to quickly enter your virtual env, make sure you name your venv `localenv` as well! If you name your venv anything other than `localenv` make sure to edit the `env` bash script)

Install libraries 

`pip -r requirements.txt`

Make sure that there are two directories already present `client_data` and `server_data` if not create them and run `setup.py`, this file should only be run once as it will generate the certificate and key for the server.

### **HOW TO RUN**

After installing all the required libraries open two terminal panes, start `python3 server.py` to fire up the server first then in the second window run `python3 client.py` to start the handshake process by the client.
