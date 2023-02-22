from flask import Flask, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api
from Server.Resources.resources import Endpoint_API


app = Flask(__name__)
app.config['SECRET_KEY'] = '696969'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = 'secret key'
api = Api(app)
db = SQLAlchemy(app)

api.add_resource(Endpoint_API, "/api")

try:
    db.create_all()
except Exception as e:
    pass