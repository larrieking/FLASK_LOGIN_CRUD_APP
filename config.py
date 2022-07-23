from flask import Flask
from flask_pymongo import PyMongo


def configurations():
    app = Flask(__name__)
    app.config[
        "MONGO_URI"] = "<manoddb_atlas login url>"
    app.secret_key = 'Allah198612345678'
    return app


def db_configuration():
    return PyMongo(configurations())
