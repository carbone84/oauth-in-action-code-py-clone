# oauth-in-action-code-py-clone
This is a project to convert the exercise code from the OAuth In Action book by Justin Richer and Antonio Sanso into Python using Flask.
The original repo can be found at https://github.com/oauthinaction/oauth-in-action-code.

### To use the code as written, you will need to create 3 virtual environments for each exercise, and then run flask in each virtual environment.
To work the ch-3-ex-1 exercise, create a virtual environment in the authorization_server, client, and protected_resource directories.  
##### In the client directory, create the virtual environment and activate it:  
    python3 -m venv client-env
    source client-env/bin/activate  
You will need to install flask, python-dotenv, and requests  
    pip install flask python-dotenv requests  
Then you can run flask  
    flask run  
This will create the client at http://localhost:5000/

##### In the authorization_server directory:  
    python3 -m venv authorization-env
    source authorization-env/bin/activate  
You will need to install flask, python-dotenv, and tinydb  
    pip install flask python-dotenv tinydb  
Then you can run flask  
    flask run  
This will create the authorization server at http://localhost:5001/

##### In the protected_resource directory:  
    python3 -m venv resource-env
    source resource-env/bin/activate  
You will need to install flask, python-dotenv, and tinydb  
    pip install flask python-dotenv tinydb  
Then you can run flask  
    flask run  
This will create the protected resource at http://localhost:5002/

##### You will need to follow similar setup for the rest of the exercises as well.