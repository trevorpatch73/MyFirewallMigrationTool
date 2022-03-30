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
from typing import List
import requests
import json
import re
import secrets

from flask import Flask, render_template, redirect, url_for, render_template, request, session, flash
from flask_wtf import FlaskForm
from wtforms import Form, BooleanField, StringField, PasswordField, validators, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired
from wtforms.widgets import TextArea
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

    # id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    db_serial_number = db.Column(db.String(200), primary_key=True)
    db_host_name = db.Column(db.String(300), nullable=True)
    db_mgmt_ip = db.Column(db.String(20), nullable=True)
    db_make = db.Column(db.String(300), nullable=True)
    db_model = db.Column(db.String(300), nullable=True)
    db_state = db.Column(db.String(50), nullable=True)

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

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'), nullable=False)


class FIREWALL_NATS_TABLE(db.Model):
    __tablename__ = "FIREWALL_NATS_TABLE"

    db_type = db.Column(db.String(10), primary_key=True)
    db_original_ip = db.Column(db.String(20), primary_key=True)
    db_translated_ip = db.Column(db.String(20), primary_key=True)
    db_rule_name = db.Column(db.String(300), nullable=True, unique=True)
    db_state = db.Column(db.String(50), nullable=True, unique=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'), nullable=False)


class FIREWALL_ROUTES_TABLE(db.Model):
    __tablename__ = "FIREWALL_ROUTES_TABLE"

    db_network_prefix = db.Column(db.String(20), primary_key=True)
    db_subnet = db.Column(db.String(20), primary_key=True)
    db_next_hop = db.Column(db.String(20), primary_key=True)
    db_admin_distance = db.Column(db.String(4), primary_key=True)
    db_name = db.Column(db.String(300), nullable=True, unique=True)
    db_state = db.Column(db.String(50), nullable=True, unique=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'), nullable=False)


# Create Database if it doesn't exist
if not path.exists('sqlite-firewall.db'):
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
        'Hostname: ', [validators.Length(min=0, max=300)])
    fm_mgmt_ip = StringField(
        'Management IP: ', [validators.Length(min=0, max=20)])
    fm_make = StringField('Make: ', [validators.Length(min=0, max=300)])
    fm_model = StringField('Model: ', [validators.Length(min=0, max=300)])
    submit = SubmitField('Submit')


class FIREWALL_RULES_TEXT_FORM(FlaskForm):
    fm_serial_number = StringField(
        'Serial Number: ', [validators.Length(min=1, max=200)])
    fm_input_txt = StringField(
        'Copy/Paste CLI Section: ', [validators.Length(min=1, max=1000000)], widget=TextArea())
    submit = SubmitField('Submit')


class FIREWALL_NATS_TEXT_FORM(FlaskForm):
    fm_serial_number = StringField(
        'Serial Number: ', [validators.Length(min=1, max=200)])
    fm_input_txt = StringField(
        'Copy/Paste CLI Section: ', [validators.Length(min=1, max=1000000)], widget=TextArea())
    submit = SubmitField('Submit')


class FIREWALL_ROUTES_TEXT_FORM(FlaskForm):
    fm_serial_number = StringField(
        'Serial Number: ', [validators.Length(min=1, max=200)])
    fm_input_txt = StringField(
        'Copy/Paste CLI Section: ', [validators.Length(min=1, max=1000000)], widget=TextArea())
    submit = SubmitField('Submit')


########################
### ROUTE DECORATORS ###
########################


# Invalid URI & Error Handling
@ app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@ app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


# Server Root Redirect towards home
@ app.route("/")
def root():
    return redirect(url_for("home"))


# Home Directory
@ app.route("/home", methods=['GET', 'POST'],)
def home():
    signal = None

    if request.method == 'POST':
        if request.form['submit_button'] == 'Firewall Inventory':
            return redirect(url_for('FIREWALL_INVENTORY'))
        if request.form['submit_button'] == 'Firewall Rules':
            return redirect(url_for('FIREWALL_RULES_TEXT'))
        if request.form['submit_button'] == 'Firewall NATs':
            return redirect(url_for('FIREWALL_NATS_TEXT'))
        if request.form['submit_button'] == 'Firewall Routes':
            return redirect(url_for('FIREWALL_ROUTES_TEXT'))

    return render_template(
        "home.html",
        signal=signal
    )


# Firewall Inventory
@ app.route("/firewall/inventory", methods=['GET', 'POST'],)
def FIREWALL_INVENTORY():
    serial_number = None
    host_name = None
    mgmt_ip = None
    make = None
    model = None
    state = None
    signal = None
    form = FIREWALL_INVENTORY_FORM()

    if request.method == 'POST':
        if form.validate_on_submit():
            serial_number = form.fm_serial_number.data
            host_name = form.fm_host_name.data
            mgmt_ip = form.fm_mgmt_ip.data
            make = form.fm_make.data
            model = form.fm_model.data
            fw_applicance = FIREWALL_INVENTORY_TABLE.query.filter_by(
                db_serial_number=serial_number).first()
            if fw_applicance is None:
                entry = FIREWALL_INVENTORY_TABLE(
                    db_serial_number=serial_number,
                    db_host_name=host_name,
                    db_mgmt_ip=mgmt_ip,
                    db_make=make,
                    db_model=model,
                    db_state='new'
                )
                db.session.add(entry)
                db.session.commit()
                signal = 'info'
                flash(
                    f"New Firewall, {serial_number}:{host_name}, successfully added to database!")
                return redirect(url_for('FIREWALL_INVENTORY'))
            else:

                if host_name != '' and serial_number != '':
                    fw_applicance.db_host_name = host_name
                    db.session.commit()
                    signal = 'info'
                    flash(
                        f"Hostname, {host_name}, for firewall, {serial_number}, has been updated")
                if mgmt_ip != '' and serial_number != '':
                    fw_applicance.db_mgmt_ip = mgmt_ip
                    db.session.commit()
                    signal = 'info'
                    flash(
                        f"Management IP, {mgmt_ip}, for firewall, {serial_number}, has been updated")
                if make != '' and serial_number != '':
                    fw_applicance.db_make = make
                    db.session.commit()
                    signal = 'info'
                    flash(
                        f"Make, {make}, for firewall, {serial_number}, has been updated")
                if model != '' and serial_number != '':
                    fw_applicance.db_model = model
                    db.session.commit()
                    signal = 'info'
                    flash(
                        f"Model, {model}, for firewall, {serial_number}, has been updated")

                if host_name != '' and serial_number == '':
                    signal = 'error'
                    flash(
                        "Serial number, primary key, cannot be null when updating the hostname.")
                if mgmt_ip != '' and serial_number == '':
                    signal = 'error'
                    flash(
                        "Serial number, primary key, cannot be null when updating the management ip.")
                if make != '' and serial_number == '':
                    signal = 'error'
                    flash(
                        "Serial number, primary key, cannot be null when updating the make.")
                if model != '' and serial_number == '':
                    signal = 'error'
                    flash(
                        "Serial number, primary key, cannot be null when updating the model.")
                if serial_number != '' and host_name == '' and mgmt_ip == '' and make == '' and model == '':
                    signal = 'error'
                    flash(
                        "Serial Number is the Primary Key for the Firewall Inventory Table. You cannot only update this field.")

    return render_template(
        "fw_inv.html",
        form=form,
        signal=signal
    )


# Firewall Rules - Text Input
@app.route("/firewall/rules/text", methods=['GET', 'POST'],)
def FIREWALL_RULES_TEXT():
    serial_number = None
    input_txt = None
    signal = None
    form = FIREWALL_RULES_TEXT_FORM()

    if request.method == 'POST':
        if form.validate_on_submit():
            serial_number = form.fm_serial_number.data
            input_txt = form.fm_input_txt.data

    return render_template(
        "fw_rules_text.html",
        form=form,
        signal=signal
    )


# Firewall NATs - Text Input
@app.route("/firewall/nats/text", methods=['GET', 'POST'],)
def FIREWALL_NATS_TEXT():
    signal = None
    form = FIREWALL_NATS_TEXT_FORM()

    return render_template(
        "fw_nats_text.html",
        form=form,
        signal=signal
    )


# Firewall RULES - Text Input
@app.route("/firewall/rules/text", methods=['GET', 'POST'],)
def FIREWALL_ROUTES_TEXT():
    signal = None
    form = FIREWALL_ROUTES_TEXT_FORM()

    return render_template(
        "fw_rules_text.html",
        form=form,
        signal=signal
    )


########################
### START WEB SERVER ###
########################
if __name__ == "__main__":
    app.run(debug=True)
