###############################
### PY INSTALL REQUIREMENTS ###
###############################
# pip install flask
# pip install flask-sqlalchemy
# pip install flask-wtf

from os import path
from pathlib import Path
from time import sleep
from datetime import datetime
import requests
import json
import re
import secrets

from flask import *
from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from flask_sqlalchemy import SQLAlchemy

DB_NAME = 'sqlite-firewall.db'

############################
### START FLASK INSTANCE ###
############################
app = Flask(__name__)
app.config['SECRET_KEY'] = str(secrets.token_hex(128))
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
db.init_app(app)


#############################
### SQLITE DB DATA MODELS ###
#############################

class FIREWALL_INVENTORY_TABLE(db.Model):
    __tablename__ = "FIREWALL_INVENTORY_TABLE"

    db_serial_number = db.Column(db.String(200), primary_key=True)
    db_host_name = db.Column(db.String(300), nullable=True, unique=True)
    db_mgmt_ip = db.Column(db.String(20), nullable=True, unique=True)
    db_make = db.Column(db.String(300), nullable=True, unique=True)
    db_model = db.Column(db.String(300), nullable=True, unique=True)
    db_state = db.Column(db.String(50), nullable=True, unique=True)

    FIREWALL_RULES_TABLE = db.relationship('FIREWALL_RULES_TABLE')
    FIREWALL_NATS_TABLE = db.relationship('FIREWALL_NATS_TABLE')
    FIREWALL_ROUTES_TABLE = db.relationship('FIREWALL_ROUTES_TABLE')


class FIREWALL_RULES_TABLE(db.Model):
    __tablename__ = "FIREWALL_RULES_TABLE"

    db_source_ip = db.Column(db.String(20), primary_key=True)
    db_destination_ip = db.Column(db.String(20), primary_key=True)
    db_protocol = db.Column(db.String(5), primary_key=True)
    db_port_number = db.Column(db.String(7), primary_key=True)
    db_rule_name = db.Column(db.String(300), nullable=True, unique=True)
    db_state = db.Column(db.String(50), nullable=True, unique=True)

    db_serial_number = db.Column(db.string, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'), nullable=False)


class FIREWALL_NATS_MODEL(db.Model):
    __tablename__ = "FIREWALL_NATS_TABLE"

    db_type = db.Column(db.String(10), primary_key=True)
    db_original_ip = db.Column(db.String(20), primary_key=True)
    db_translated_ip = db.Column(db.String(20), primary_key=True)
    db_rule_name = db.Column(db.String(300), nullable=True, unique=True)
    db_state = db.Column(db.String(50), nullable=True, unique=True)

    db_serial_number = db.Column(db.string, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'), nullable=False)


class FIREWALL_ROUTES_TABLE(db.Model):
    __tablename__ = "FIREWALL_ROUTES_TABLE"

    db_network_prefix = db.Column(db.String(20), primary_key=True)
    db_subnet = db.Column(db.String(20), primary_key=True)
    db_next_hop = db.Column(db.String(20), primary_key=True)
    db_admin_distance = db.Column(db.String(4), primary_key=True)
    db_name = db.Column(db.String(300), nullable=True, unique=True)
    db_state = db.Column(db.String(50), nullable=True, unique=True)

    db_serial_number = db.Column(db.string, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'), nullable=False)


# Create Database if it doesn't exist
if not path.exists('sqlite.db'):
    db.create_all()
    print('Created Database!')
else:
    print('Database Exists!')

##################################
### WHAT THE FORMS (FLASK-WTF) ###
##################################


class FIREWALL_INVENTORY_FORM(FlaskForm):
    fm_serial_number = StringField(
        'Serial Number: ', [validators.Length(min=1, max=200)])
    fm_host_name = StringField(
        'Hostname: ', [validators.Length(min=1, max=300)])
    fm_mgmt_ip = StringField(
        'Management IP: ', [validators.Length(min=1, max=20)])
    fm_make = StringField('Make: ', [validators.Length(min=1, max=300)])
    fm_model = StringField('Model: ', [validators.Length(min=1, max=300)])
    submit = SubmitField('Submit')


class FIREWALL_RULES_TEXT_FORM(FlaskForm):
    fm_input_txt = StringField(
        'Serial Number: ', [validators.Length(min=1, max=1000000)])
    submit = SubmitField('Submit')


class FIREWALL_NATS_TEXT_FORM(FlaskForm):
    fm_input_txt = StringField(
        'Serial Number: ', [validators.Length(min=1, max=1000000)])
    submit = SubmitField('Submit')


class FIREWALL_ROUTES_TEXT_FORM(FlaskForm):
    fm_input_txt = StringField(
        'Serial Number: ', [validators.Length(min=1, max=1000000)])
    submit = SubmitField('Submit')


########################
### ROUTE DECORATORS ###
########################


# Invalid URI & Error Handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


# Server Root Redirect towards home
@app.route("/")
def root():
    return redirect(url_for("home"))


# Home Directory
@app.route("/home", methods=['GET', 'POST'],)
def home():
    return render_template(
        "home.html",
    )

# Firewall Inventory


@app.route("/firewall/inventory", methods=['GET', 'POST'],)
def FIREWALL_INVENTORY():
    return render_template(
        "fw_inv.html",
    )

# Firewall Rules - Text Input


@app.route("/firewall/rules/text", methods=['GET', 'POST'],)
def FIREWALL_RULES_TEXT():
    return render_template(
        "fw_rules_text.html",
    )

# Firewall NATs - Text Input


@app.route("/firewall/nats/text", methods=['GET', 'POST'],)
def FIREWALL_NATS_TEXT():
    return render_template(
        "fw_nats_text.html",
    )

# Firewall RULES - Text Input


@app.route("/firewall/rules/text", methods=['GET', 'POST'],)
def FIREWALL_RULES_TEXT():
    return render_template(
        "fw_rules_text.html",
    )


########################
### START WEB SERVER ###
########################
if __name__ == "__main__":
    app.run(debug=True)
