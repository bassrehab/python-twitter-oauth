# Python App to demonstrate Twitter OAuth

A simple app using Python-Flask that logs in an user using Twitter account, displays the user tweets and posts tweets using the Twitter API. A POC barebones implementation.

### Running the Code

1. Clone this repo.
   ```sh
    git clone https://github.com/bassrehab/python-twitter-oauth.git
   ```

2. Make sure dependencies are installed. Code was tested on Python 2.7.X

    ```sh
    pip install flask
    pip install twitter
    ```
3. Create a twitter app, fetch app consumer token/secrets and enter in web.py.

4. Run, change debug/production mode.
    ```sh
    $ python web.py
    ```

### Interact
Fire up your browser and visit http://127.0.0.0:5000
or visit for a live version:  http://ec2-54-200-242-227.us-west-2.compute.amazonaws.com


