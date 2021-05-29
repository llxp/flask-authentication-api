from flask import Flask
import os
from flask_cors import CORS

from .api import app as api


# create the flask application object
application = Flask(__name__)

cors = CORS(application)

application.register_blueprint(api, url_prefix='/api/')


@application.route(
    '/api/',
    methods=['GET'])
def index(service: str, port: str, action: str):
    pass


if __name__ == '__main__':
    application.debug = True
    application.run(host='0.0.0.0', port=5002)
