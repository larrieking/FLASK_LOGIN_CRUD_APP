from flask import Flask
from flask_pymongo import PyMongo


def configurations():
    app = Flask(__name__)
    app.config[
        "MONGO_URI"] = "mongodb+srv://larryking:Elshadai1986@cluster0.vo53l.mongodb.net/user?retryWrites=true&w=majority"
    app.secret_key = 'Allah198612345678'
    return app


def db_configuration():
    return PyMongo(configurations())