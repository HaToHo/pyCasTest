from pycas import cas
from flask import Flask
from flask import redirect
from flask import request


app = Flask(__name__)

CAS_SERVER  = "https://cas.umu.se"
SERVICE_URL = "http://127.0.0.1:5000/"
myCasClient = cas(CAS_SERVER, SERVICE_URL)


@app.route('/')
def home():
    uid = myCasClient.handleCallback(request.args["ticket"])
    return 'You have logged in with userid: ' +  uid


@app.route('/caslogin')
def caslogin():
    url = myCasClient.createRedirectUrl()
    return redirect(url, 301)

if __name__ == '__main__':
    app.run()
