###############################
### PY INSTALL REQUIREMENTS ###
###############################
# pip install flask
# pip install flask-sqlalchemy
# pip install flask-wtf

from distutils.log import error
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

    FIREWALL_NATS_TABLE = db.relationship('FIREWALL_NATS_TABLE')
    FIREWALL_ROUTES_TABLE = db.relationship('FIREWALL_ROUTES_TABLE')
    FIREWALL_INTERFACES_TABLE = db.relationship('FIREWALL_INTERFACES_TABLE')
    FIREWALL_ASA_ACCESS_GROUP_TABLE = db.relationship(
        'FIREWALL_ASA_ACCESS_GROUP_TABLE')
    FIREWALL_ASA_OBJECT_NETWORK_TABLE = db.relationship(
        'FIREWALL_ASA_OBJECT_NETWORK_TABLE')
    FIREWALL_ASA_OBJECT_SERVICE_TABLE = db.relationship(
        'FIREWALL_ASA_OBJECT_SERVICE_TABLE')
    FIREWALL_ASA_RULES_ACL_TABLE = db.relationship(
        'FIREWALL_ASA_RULES_ACL_TABLE')


class FIREWALL_NATS_TABLE(db.Model):
    __tablename__ = "FIREWALL_NATS_TABLE"

    db_type = db.Column(db.String(10), primary_key=True)
    db_original_ip = db.Column(db.String(20), primary_key=True)
    db_translated_ip = db.Column(db.String(20), primary_key=True)
    db_rule_name = db.Column(db.String(300), nullable=True, unique=True)
    db_state = db.Column(db.String(50), nullable=True, unique=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'),  primary_key=True, nullable=False)


class FIREWALL_ROUTES_TABLE(db.Model):
    __tablename__ = "FIREWALL_ROUTES_TABLE"

    db_network_prefix = db.Column(db.String(20), primary_key=True)
    db_subnet = db.Column(db.String(20), primary_key=True)
    db_next_hop = db.Column(db.String(20), primary_key=True)
    db_admin_distance = db.Column(db.String(4), primary_key=True)
    db_name = db.Column(db.String(300), nullable=True)
    db_state = db.Column(db.String(50), nullable=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'),  primary_key=True, nullable=False)


class FIREWALL_INTERFACES_TABLE(db.Model):
    __tablename__ = "FIREWALL_INTERFACES_TABLE"

    db_interface_name = db.Column(db.String(20), primary_key=True)
    db_interface_ip = db.Column(db.String(20), nullable=True)
    db_interface_subnet = db.Column(db.String(20), nullable=True)
    db_interface_zone = db.Column(db.String(200), nullable=True)
    db_interface_vlan = db.Column(db.String(6), nullable=True)
    db_interface_description = db.Column(db.String(500), nullable=True)
    db_state = db.Column(db.String(50), nullable=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'),  primary_key=True, nullable=False)


class FIREWALL_ASA_ACCESS_GROUP_TABLE(db.Model):
    __tablename__ = "FIREWALL_ASA_ACCESS_GROUP_TABLE"

    db_acl_name = db.Column(db.String(500), primary_key=True)
    db_nameif_zone = db.Column(db.String(500), nullable=True)
    db_rule_direction = db.Column(db.String(500), nullable=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'),  primary_key=True, nullable=False)


class FIREWALL_ASA_OBJECT_NETWORK_TABLE(db.Model):
    __tablename__ = "FIREWALL_ASA_OBJECT_NETWORK_TABLE"

    db_object_name = db.Column(db.String(500), primary_key=True)
    db_object_description = db.Column(db.String(1000), nullable=True)
    db_object_type = db.Column(db.String(200), nullable=True)
    db_object_range = db.Column(db.String(200), nullable=True)
    db_object_ip = db.Column(db.String(20), primary_key=True)
    db_object_subnet = db.Column(db.String(20), primary_key=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'),  primary_key=True, nullable=False)


class FIREWALL_ASA_OBJECT_SERVICE_TABLE(db.Model):
    __tablename__ = "FIREWALL_ASA_OBJECT_SERVICE_TABLE"

    db_object_name = db.Column(db.String(500), primary_key=True)
    db_object_description = db.Column(db.String(1000), nullable=True)
    db_object_type = db.Column(db.String(200), nullable=True)
    db_object_range = db.Column(db.String(200), nullable=True)
    db_object_protocol = db.Column(db.String(50), primary_key=True)
    db_object_port = db.Column(db.String(50), primary_key=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'),  primary_key=True, nullable=False)


class FIREWALL_ASA_RULES_ACL_TABLE(db.Model):
    __tablename__ = "FIREWALL_ASA_RULES_ACL_TABLE"

    db_acl_name = db.Column(db.String(500), primary_key=True)
    db_acl_description = db.Column(db.String(1000), nullable=True)
    db_source_ip = db.Column(db.String(20), primary_key=True)
    db_source_subnet = db.Column(db.String(20), nullable=True)
    db_source_zone = db.Column(db.String(200), nullable=True)
    db_destination_ip = db.Column(db.String(20), primary_key=True)
    db_destination_subnet = db.Column(db.String(20), nullable=True)
    db_destination_zone = db.Column(db.String(200), nullable=True)
    db_flow_protocol = db.Column(db.String(50), primary_key=True)
    db_flow_port = db.Column(db.String(50), primary_key=True)
    db_firewall_action = db.Column(db.String(50), nullable=True)
    db_state = db.Column(db.String(50), nullable=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'),  primary_key=True, nullable=False)


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


class FIREWALL_ROUTES_INPUT_SHOW_ROUTE_FORM(FlaskForm):
    fm_serial_number = StringField(
        'Serial Number: ', [validators.Length(min=1, max=200)])
    fm_input_txt = StringField(
        'Copy/Paste CLI Section: ', [validators.Length(min=1, max=1000000)], widget=TextArea())
    submit = SubmitField('Submit')


class FIREWALL_INTERFACE_INPUT_RUN_CONFIG_INTERFACES_FORM(FlaskForm):
    fm_serial_number = StringField(
        'Serial Number: ', [validators.Length(min=1, max=200)])
    fm_input_txt = StringField(
        'Copy/Paste CLI Section: ', [validators.Length(min=1, max=1000000)], widget=TextArea())
    submit = SubmitField('Submit')


class FIREWALL_ASA_INPUT_RUN_CONFIG_RULES_FORM(FlaskForm):
    fm_serial_number = StringField(
        'Serial Number: ', [validators.Length(min=1, max=200)])
    fm_access_group_input_txt = StringField(
        'Copy/Paste CLI "ACCESS-GROUP" Section: ', widget=TextArea())
    fm_object_input_txt = StringField(
        'Copy/Paste CLI "OBJECT" & "OBJECT-GROUP" Section: ', widget=TextArea())
    fm_acl_input_txt = StringField(
        'Copy/Paste CLI "ACCESS-CONTROL-LIST" Section: ', widget=TextArea())
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
            return redirect(url_for('FIREWALL_ROUTES_INPUT_SHOW_ROUTE'))
        if request.form['submit_button'] == 'Firewall Interfaces':
            return redirect(url_for('FIREWALL_INTERFACES_INPUT_RUN_CONFIG_INTERFACES'))

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
@app.route("/firewall/asa/rules/input/run-config-rules", methods=['GET', 'POST'],)
def FIREWALL_RULES_TEXT():
    serial_number = None
    access_group_input_tx = None
    object_input_txt = None
    acl_input_txt = None

    acl_name = None
    acl_description = None
    source_ip = None
    source_zone = None
    destination_ip = None
    destination_zone = None
    flow_protocol = None
    flow_port = None
    firewall_action = None
    state = None

    signal = None
    form = FIREWALL_ASA_INPUT_RUN_CONFIG_RULES_FORM()

    if request.method == 'POST':
        if form.validate_on_submit():
            serial_number = form.fm_serial_number.data
            access_group_input_txt = form.fm_access_group_input_txt.data
            object_input_txt = form.fm_object_input_txt.data
            acl_input_txt = form.fm_acl_input_txt.data
            inventory = FIREWALL_INVENTORY_TABLE.query.filter_by(
                db_serial_number=serial_number).first()
            if inventory is not None:
                if object_input_txt is not None:

                    built_string = ""
                    row_count = 0
                    rows = str(object_input_txt).split('\n')
                    for row in rows:
                        if row.startswith('object') or row.startswith('object'):
                            marked_string = row.replace("object", "!\nobject")
                            built_string = built_string + "\n" + marked_string
                        else:
                            built_string = built_string + "\n" + row
                        row_count += 1

                    objects = built_string.split("!")
                    object_count = 0
                    for object in objects:
                        object_name = None
                        object_type = None
                        object_description = None
                        print(f'Object[{object_count}]: {object}')

                        row_count = 0
                        rows = object.split('\n')

                        for row in rows:
                            print(f'Row[{row_count}]: {row}')
                            object_range = None
                            object_ip = None
                            object_subnet = None
                            object_protocol = None
                            object_port = None

                            if row.startswith('object') or row.startswith('object-group'):
                                cols = row.split(' ')
                                col_count = 0

                                for col in cols:
                                    print(f'Column[{col_count}]: {col}')

                                    if "object" not in col and "network" not in col and "service" not in col:
                                        if object_name is None:
                                            object_name = col
                                        else:
                                            object_name = object_name + "_" + col
                                        print(
                                            f'OBJECT NAME has been mapped to {object_name}')

                                    if col == 'network' or col == 'service':
                                        object_type = col
                                        print(
                                            f'OBJECT TYPE has been mapped to {object_type}')

                                    col_count += 1

                            if "description" in row:
                                cols = row.split(' ')
                                col_count = 0

                                for col in cols:
                                    print(f'Column[{col_count}]: {col}')

                                    if "description" not in col:
                                        if object_description is None:
                                            object_description = col
                                        else:
                                            object_description = object_description + "_" + col
                                            print(
                                                f'OBJECT DESCRIPTION has been mapped to {object_description}')

                                    col_count += 1

                            if "network" in object:
                                if not row.startswith('object') or not row.startswith('object-group'):
                                    if "subnet" in row:
                                        cols = row.split(' ')
                                        col_count = 0

                                        dot_dec_pattern = re.compile(
                                            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

                                        for col in cols:
                                            print(
                                                f'Column[{col_count}]: {col}')

                                            if "subnet" in col:
                                                object_range = col
                                                print(
                                                    f'Range is mapped to: {object_range}')

                                            result_filter = dot_dec_pattern.search(
                                                col)
                                            if result_filter:
                                                if col.startswith('255'):
                                                    object_subnet = col
                                                    print(
                                                        f'Subnet is mapped to: {object_subnet}')
                                                if not col.startswith('255') and '0.0.0.0' not in row:
                                                    object_ip = col
                                                    print(
                                                        f'IP is mapped to: {object_ip}')
                                                if "0.0.0.0 0.0.0.0" in row:
                                                    object_ip = "0.0.0.0"
                                                    print(
                                                        f'IP is mapped to: {object_ip}')
                                                    object_subnet = "0.0.0.0"
                                                    print(
                                                        f'Subnet is mapped to: {object_subnet}')

                                            col_count += 1

                                    if "host" in row:
                                        cols = row.split(' ')
                                        col_count = 0
                                        dot_dec_pattern = re.compile(
                                            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

                                        for col in cols:
                                            print(
                                                f'Column[{col_count}]: {col}')

                                            if "host" in col:
                                                object_range = col
                                                print(
                                                    f'Range is mapped to: {object_range}')

                                            result_filter = dot_dec_pattern.search(
                                                col)
                                            if result_filter:
                                                object_ip = col
                                                print(
                                                    f'Host IP is mapped to: {object_ip}')
                                                object_subnet = "255.255.255.255"
                                                print(
                                                    f'Host Subnet is mapped to: {object_subnet}')

                                            col_count += 1

                                    if object_name is not None and object_ip is not None and object_subnet is not None:
                                        netobj = FIREWALL_ASA_OBJECT_NETWORK_TABLE.query.filter_by(
                                            db_object_name=object_name,
                                            db_object_description=object_description,
                                            db_object_type=object_type,
                                            db_object_range=object_range,
                                            db_object_ip=object_ip,
                                            db_object_subnet=object_subnet,
                                            db_serial_number=serial_number
                                        ).first()
                                        if netobj is None:
                                            entry = FIREWALL_ASA_OBJECT_NETWORK_TABLE(
                                                db_object_name=object_name,
                                                db_object_description=object_description,
                                                db_object_type=object_type,
                                                db_object_range=object_range,
                                                db_object_ip=object_ip,
                                                db_object_subnet=object_subnet,
                                                db_serial_number=serial_number
                                            )
                                            db.session.add(entry)
                                            db.session.commit()
                                            signal = 'info'
                                            flash(
                                                f'New Network Object, {object_name}:{object_range}:{object_ip}:{object_subnet}, for firewall, {serial_number}')

                            if "service" in object:
                                if not row.startswith('object') or not row.startswith('object-group'):
                                    if "service" in row:
                                        cols = row.split(' ')
                                        col_count = 0

                                        for col in cols:
                                            print(
                                                f'Column[{col_count}]: {col}')

                                            if "service" in col:
                                                object_range = col
                                                print(
                                                    f'Range is mapped to: {object_range}')

                                            if "tcp" in col or "udp" in col or "icmp" in col or "ip" in col:
                                                object_protocol = col
                                                print(
                                                    f'Protocol is mapped to: {object_protocol}')

                                            if "service" not in col or str(object_protocol) not in col or "source" not in col or "destination" not in col or "eq" in col or str(object_name) not in col:
                                                nonwhite_pattern = re.compile(
                                                    r'(\w+)')
                                                result_filter = nonwhite_pattern.search(
                                                    col)
                                                if result_filter:
                                                    object_port = col
                                                    print(
                                                        f'Port is mapped to: {object_port}')

                                            col_count += 1

                                    if "port-object" in row:
                                        cols = row.split(' ')
                                        col_count = 0

                                        for col in cols:
                                            print(
                                                f'Column[{col_count}]: {col}')

                                            if "port-object" in col:
                                                object_range = col
                                                print(
                                                    f'Range is mapped to: {object_range}')

                                            if "tcp" in object_name:
                                                object_protocol = "tcp"

                                            if "udp" in object_name:
                                                object_protocol = "udp"

                                            if "icmp" in object_name:
                                                object_protocol = "icmp"

                                            if "port-object" not in col or "source" not in col or "destination" not in col or "eq" in col or str(object_name) not in col:
                                                nonwhite_pattern = re.compile(
                                                    r'(\w+)')
                                                result_filter = nonwhite_pattern.search(
                                                    col)
                                                if result_filter:
                                                    object_port = col
                                                    print(
                                                        f'Port is mapped to: {object_port}')

                                            col_count += 1

                                    if object_name is not None and object_protocol is not None and object_port is not None:
                                        srvobj = FIREWALL_ASA_OBJECT_SERVICE_TABLE.query.filter_by(
                                            db_object_name=object_name,
                                            db_object_description=object_description,
                                            db_object_type=object_type,
                                            db_object_range=object_range,
                                            db_object_protocol=object_protocol,
                                            db_object_port=object_port,
                                            db_serial_number=serial_number
                                        ).first()

                                        if srvobj is None:
                                            if object_name != object_protocol or object_name != object_port:
                                                entry = FIREWALL_ASA_OBJECT_SERVICE_TABLE(
                                                    db_object_name=object_name,
                                                    db_object_description=object_description,
                                                    db_object_type=object_type,
                                                    db_object_range=object_range,
                                                    db_object_protocol=object_protocol,
                                                    db_object_port=object_port,
                                                    db_serial_number=serial_number
                                                )

                                                db.session.add(entry)
                                                db.session.commit()
                                                signal = 'info'
                                                flash(
                                                    f'New Service Object, {object_name}:{object_range}:{object_protocol}:{object_port}, for firewall, {serial_number}')

                        object_count += 1

                if access_group_input_txt is not None:
                    print(access_group_input_txt)
                    rows = str(access_group_input_txt).split('\n')
                    row_count = 0

                    for row in rows:

                        cols = row.split(' ')
                        col_count = 0
                        print(cols)

                        for col in cols:
                            print(f'Column[{col_count}]: {col}')
                            col_count += 1

                        nonwhite_pattern = re.compile(r'(\w+)')

                        result_filter = nonwhite_pattern.search(col)

                        if result_filter:
                            acl_name = str(cols[1])
                            print(f'ACL Name is mapped too: {acl_name}')

                            rule_direction = str(cols[2])
                            print(
                                f'Rule Direction is mapped too: {rule_direction}')

                            nameif_zone = str(cols[4])
                            print(f'Zone is mapped too: {nameif_zone}')

                            group = FIREWALL_ASA_ACCESS_GROUP_TABLE.query.filter_by(
                                db_acl_name=acl_name,
                                db_serial_number=serial_number
                            ).first()

                            if group is None:
                                entry = FIREWALL_ASA_ACCESS_GROUP_TABLE(
                                    db_acl_name=acl_name,
                                    db_nameif_zone=nameif_zone,
                                    db_rule_direction=rule_direction,
                                    db_serial_number=serial_number
                                )
                                db.session.add(entry)
                                db.session.commit()
                                signal = 'info'
                                flash(
                                    f'New Access-Group, {acl_name}:{rule_direction}:{nameif_zone}, for firewall, {serial_number}')

                        row_count += 1

                if acl_input_txt is not None:
                    acc_grps = FIREWALL_ASA_ACCESS_GROUP_TABLE.query.filter_by(
                        db_serial_number=serial_number).with_entities(FIREWALL_ASA_ACCESS_GROUP_TABLE.db_acl_name).all()

                    print(acc_grps)

                    entry_count = 0
                    for acc_grp in acc_grps:
                        acc_grp = str(acc_grp).replace("('", "")
                        acc_grp = str(acc_grp).replace("',)", "")
                        print(f'Entry[{entry_count}]: {acc_grp}')
                        entry_count += 1

                        acls = str(acl_input_txt).split('\n')
                        acl_count = 0

                        for acl in acls:
                            if str(acc_grp) in acl:
                                print(
                                    f'Access-Group, {acc_grp} detected in ACL')
                                print(f'ACL: {acl}')

                                if "remark" not in acl:

                                    cols = acl.split(' ')
                                    col_count = 0

                                    for col in cols:
                                        print(f'Column[{col_count}]: {col}')

                                        acl_name = (
                                            str(cols[1]) + "-Line-" + str(acl_count+1))
                                        firewall_action = str(cols[3])
                                        flow_protocol = str(cols[4])

                                        dot_dec_pattern = re.compile(
                                            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

                                        if col_count == 5:
                                            dot_dec_filter = dot_dec_pattern.search(
                                                col)

                                            if dot_dec_filter:
                                                source_ip = str(cols[5])
                                                source_subnet = str(cols[6])
                                            if "any" in col:
                                                source_ip = str(cols[5])
                                                source_subnet = "any"
                                            if "object" in col:
                                                source_ip = str(cols[6])
                                                source_subnet = "object"
                                            if "host" in col:
                                                source_ip = str(
                                                    cols[6])
                                                source_subnet = "255.255.255.255"

                                        if col_count > 5:
                                            dot_dec_filter = dot_dec_pattern.search(
                                                col)

                                            if dot_dec_filter:
                                                destination_ip = str(
                                                    cols[col_count])
                                                dot_dec_filter_2 = dot_dec_pattern.search(
                                                    cols[col_count+1])
                                                if dot_dec_filter_2:
                                                    destination_subnet = str(
                                                        cols[col_count+1])

                                            if "any" in col:
                                                destination_ip = str(
                                                    cols[col_count])
                                                destination_subnet = "any"

                                            if "object" in col:
                                                destination_ip = str(
                                                    cols[col_count+1])
                                                destination_subnet = "object"

                                            if "host" in col:
                                                destination_ip = str(
                                                    cols[col_count+1])
                                                destination_subnet = "255.255.255.255"

                                        if "eq" in col:
                                            flow_port = str(cols[col_count+1])

                                        if "range" in col:
                                            flow_port = (str(cols[col_count+1]) +
                                                         "-" + str(cols[col_count+2]))

                                        if ("object-group" or "object-group service") in acl and flow_port != 'any' and len(cols) > 8:

                                            non_white_pattern = re.compile(
                                                r'(\w+)')

                                            po5_non_white = non_white_pattern.search(
                                                cols[5])
                                            po6_non_white = non_white_pattern.search(
                                                cols[6])
                                            po7_non_white = non_white_pattern.search(
                                                cols[7])
                                            po8_non_white = non_white_pattern.search(
                                                cols[8])

                                            if "any" in cols[5] and "any" in cols[6]:
                                                if "object-group" in acl and "object-group service" not in acl:
                                                    flow_port = str(cols[8])

                                                if "object-group service" in acl:
                                                    flow_port = str(cols[9])

                                            if (str(po5_non_white) and str(po6_non_white) and str(po7_non_white) and str(po8_non_white)) in acl and "any" not in acl and len(cols) > 8:
                                                if "object-group" in acl and "object-group service" not in acl:
                                                    flow_port = str(cols[10])

                                                if "object-group service" in acl:
                                                    flow_port = str(cols[11])

                                            if "any" in (cols[5] or cols[7]) and len(cols) > 9:
                                                if "object-group" in acl and "object-group service" not in acl:
                                                    flow_port = str(cols[9])

                                                if "object-group service" in acl:
                                                    flow_port = str(cols[10])

                                        if acl.count('object-group') == 3 and "object-group service" not in acl and flow_port != 'any':
                                            flow_protocol = "object"
                                            flow_port = cols[5]

                                            result = FIREWALL_ASA_OBJECT_SERVICE_TABLE.query.filter_by(
                                                db_serial_number=serial_number, db_object_name=flow_port).first()

                                            if result is not None:
                                                flow_protocol = 'ERROR'
                                                flow_port = 'ERROR'

                                        if "lt" not in acl:
                                            if "gt" not in acl:
                                                if "eq" not in acl:
                                                    if "neq" not in acl:
                                                        if "range" not in acl:
                                                            if "object-group service" not in acl:
                                                                if acl.count('object-group') != 3:
                                                                    flow_port = 'any'

                                        col_count += 1
                                if "remark" in acl and ("permit" or "deny") in acl:
                                    objects = acl.split(":")
                                    object_count = 0

                                    for object in objects:
                                        print(
                                            f'Object[{object_count}]: {object}')

                                        if ("permit" or "deny") in object:

                                            cols = object.split(' ')
                                            col_count = 0

                                            for col in cols:
                                                print(
                                                    f'Column[{col_count}]: {col}')

                                                firewall_action = str(cols[1])
                                                flow_protocol = str(cols[2])

                                                if col_count == 3:
                                                    dot_dec_filter = dot_dec_pattern.search(
                                                        col)

                                                    if dot_dec_filter:
                                                        source_ip = str(
                                                            cols[3])
                                                        source_subnet = str(
                                                            cols[4])
                                                    if "any" in col:
                                                        source_ip = str(
                                                            cols[3])
                                                        source_subnet = "any"
                                                    if "object" in col:
                                                        source_ip = str(
                                                            cols[4])
                                                        source_subnet = "object"
                                                    if "host" in col:
                                                        destination_ip = str(
                                                            cols[col_count+1])
                                                        destination_subnet = "255.255.255.255"

                                                if col_count > 3:
                                                    dot_dec_filter = dot_dec_pattern.search(
                                                        col)

                                                    if dot_dec_filter:
                                                        destination_ip = str(
                                                            cols[col_count])
                                                        if len(cols) > 6:
                                                            dot_dec_filter_2 = dot_dec_pattern.search(
                                                                cols[col_count+1])
                                                            if dot_dec_filter_2:
                                                                destination_subnet = str(
                                                                    cols[col_count+1])
                                                    if "any" in col:
                                                        destination_ip = str(
                                                            cols[col_count])
                                                        destination_subnet = "any"
                                                    if "object" in col:
                                                        destination_ip = str(
                                                            cols[col_count+1])
                                                        destination_subnet = "object"
                                                    if "host" in col:
                                                        destination_ip = str(
                                                            cols[col_count+1])
                                                        destination_subnet = "255.255.255.255"

                                                if ("lt" or "gt" or "eq" or "neq") in col:
                                                    flow_port = str(
                                                        cols[col_count+1])

                                                if "range" in col:
                                                    flow_port = (str(cols[col_count+1]) +
                                                                 "-" + str(cols[col_count+2]))

                                                if "lt" not in acl:
                                                    if "gt" not in acl:
                                                        if "eq" not in acl:
                                                            if "neq" not in acl:
                                                                if "range" not in acl:
                                                                    if "object-group service" not in acl:
                                                                        flow_port = 'any'

                                                if ("object-group" or "object-group service") in acl and len(cols) > 6:

                                                    non_white_pattern = re.compile(
                                                        r'(\w+)')

                                                    po3_non_white = non_white_pattern.search(
                                                        cols[3])
                                                    po4_non_white = non_white_pattern.search(
                                                        cols[4])
                                                    po5_non_white = non_white_pattern.search(
                                                        cols[5])
                                                    po6_non_white = non_white_pattern.search(
                                                        cols[6])

                                                    if "any" in cols[3] and "any" in cols[4]:
                                                        if "object-group" in acl and "object-group service" not in acl:
                                                            flow_port = str(
                                                                cols[2])

                                                        if "object-group service" in acl:
                                                            flow_port = str(
                                                                cols[2])

                                                    if (str(po3_non_white) and str(po4_non_white) and str(po5_non_white) and str(po6_non_white)) in acl and "any" not in acl and len(cols) > 6:
                                                        if "object-group" in acl and "object-group service" not in acl:
                                                            flow_port = str(
                                                                cols[8])

                                                        if "object-group service" in acl:
                                                            flow_port = str(
                                                                cols[9])

                                                    if "any" in (cols[3] or cols[5]):
                                                        if "object-group" in acl and "object-group service" not in acl:
                                                            flow_port = str(
                                                                cols[7])

                                                        if "object-group service" in acl:
                                                            flow_port = str(
                                                                cols[8])

                                                col_count += 1

                                        object_count += 1
                                if acl_name is not None and source_ip is not None and source_subnet is not None and destination_ip is not None and destination_subnet is not None and flow_protocol is not None and flow_port is not None and firewall_action is not None:
                                    print(
                                        f'ACL NAME IS MAPPED TOO:           {acl_name}')
                                    print(
                                        f'SOURCE_IP IS MAPPED TOO:          {source_ip}')
                                    print(
                                        f'SOURCE_SUBNET IS MAPPED TOO:      {source_subnet}')
                                    print(
                                        f'DESTINATION_IP IS MAPPED TOO:     {destination_ip}')
                                    print(
                                        f'DESTINATION_SUBNET IS MAPPED TOO: {destination_subnet}')
                                    print(
                                        f'PROTOCOL IS MAPPED TOO:           {flow_protocol}')
                                    print(
                                        f'PORT IS MAPPED TOO:               {flow_port}')
                                    print(
                                        f'ACTION IS MAPPED TOO:             {firewall_action}')

                                    db_access_groups = FIREWALL_ASA_ACCESS_GROUP_TABLE.query.filter_by(
                                        db_serial_number=serial_number, db_acl_name=acc_grp).first()

                                    print(db_access_groups)

                                    if db_access_groups is None:
                                        print("-------------------")
                                        print("-------------------")
                                        print("-------------------")
                                        print("ERROR")
                                        print("-------------------")
                                        print("-------------------")
                                        print("-------------------")

                                    else:
                                        direction = db_access_groups.db_rule_direction

                                        if direction == 'in':
                                            source_zone = db_access_groups.db_nameif_zone
                                            destination_zone = 'any'
                                        elif direction == 'out':
                                            source_zone = 'any'
                                            destination_zone = db_access_groups.db_nameif_zone
                                        else:
                                            source_zone = 'any'
                                            destination_zone = 'any'

                                    result = FIREWALL_ASA_RULES_ACL_TABLE.query.filter_by(
                                        db_serial_number=serial_number, db_acl_name=acl_name, db_source_ip=source_ip, db_destination_ip=destination_ip, db_flow_protocol=flow_protocol, db_flow_port=flow_port).first()

                                    if result is None:
                                        entry = FIREWALL_ASA_RULES_ACL_TABLE(
                                            db_acl_name=acl_name,
                                            db_acl_description='ASA RULE MIGRATED VIA PRESIDIO AUTOMATION',
                                            db_source_ip=source_ip,
                                            db_source_subnet=source_subnet,
                                            db_source_zone=source_zone,
                                            db_destination_ip=destination_ip,
                                            db_destination_subnet=destination_subnet,
                                            db_destination_zone=destination_zone,
                                            db_flow_protocol=flow_protocol,
                                            db_flow_port=flow_port,
                                            db_firewall_action=firewall_action,
                                            db_state='new',
                                            db_serial_number=serial_number
                                        )
                                        db.session.add(entry)
                                        db.session.commit()
                                        signal = 'info'
                                        flash(
                                            f'New Firewall Rule, {acl_name}, added for firewall, {serial_number}')

                                else:
                                    print(
                                        'THE FOLLOWING ACL COULD NOT BE PROCESSED:')
                                    print(f'{acl}')
                                    signal = 'error'
                                    flash(
                                        f'THE FOLLOWING ACL COULD NOT BE PROCESSED: {acl}')

                            acl_count += 1
            else:
                signal = 'error'
                flash(
                    f"Serial Number, {serial_number}, is not in the database. Please add the inventory first.")

    return render_template(
        "fw_asa_input_run_config_rules.html",
        form=form,
        signal=signal
    )


# Firewall NATs - Text Input
@app.route("/firewall/asa/nats/text", methods=['GET', 'POST'],)
def FIREWALL_NATS_TEXT():
    serial_number = None
    input_txt = None
    signal = None
    form = FIREWALL_NATS_TEXT_FORM()

    if request.method == 'POST':
        if form.validate_on_submit():
            serial_number = form.fm_serial_number.data
            input_txt = form.fm_input_txt.data

    return render_template(
        "fw_nats_text.html",
        form=form,
        signal=signal
    )


# Firewall routes - Text Input
@app.route("/firewall/asa/routes/input/show_routes", methods=['GET', 'POST'],)
def FIREWALL_ROUTES_INPUT_SHOW_ROUTE():
    serial_number = None
    input_txt = None
    network_prefix = None
    subnet = None
    next_hop = None
    admin_distance = None
    name = None
    state = None

    signal = None
    form = FIREWALL_ROUTES_INPUT_SHOW_ROUTE_FORM()

    if request.method == 'POST':
        if form.validate_on_submit():
            serial_number = form.fm_serial_number.data
            input_txt = form.fm_input_txt.data
            inventory = FIREWALL_INVENTORY_TABLE.query.filter_by(
                db_serial_number=serial_number).first()
            if inventory is not None:
                print("----------------------")
                print("RAW STRING")
                print("----------------------")
                print(input_txt)

                print("----------------------")
                print("PATTERN FILTER")
                print("----------------------")
                double_dot_dec_pattern = re.compile(
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

                clean_input = input_txt.replace(',', '')
                rows = clean_input.split('\n')
                for row in rows:
                    result_filter = double_dot_dec_pattern.search(row)
                    if result_filter:

                        elements = row.split(' ')

                        network_prefix = elements[1]
                        subnet = elements[2]
                        next_hop = elements[5]
                        admin_distance = elements[3]
                        name = elements[6]
                        state = 'new'

                        route = FIREWALL_ROUTES_TABLE.query.filter_by(
                            db_network_prefix=network_prefix, db_subnet=subnet, db_next_hop=next_hop, db_admin_distance=admin_distance, db_serial_number=serial_number).first()

                        if route is None:
                            entry = FIREWALL_ROUTES_TABLE(
                                db_network_prefix=network_prefix,
                                db_subnet=subnet,
                                db_next_hop=next_hop,
                                db_admin_distance=admin_distance,
                                db_name=name,
                                db_state=state,
                                db_serial_number=serial_number
                            )
                            db.session.add(entry)
                            db.session.commit()
                            signal = 'info'
                            flash(
                                f"New route, {network_prefix} {subnet} via {next_hop}, added to database for firewall, {serial_number}")
                        else:
                            signal = 'error'
                            flash(
                                f"Route, {network_prefix} {subnet} via {next_hop}, already exists for firewall, {serial_number} ")

                return redirect(url_for('FIREWALL_ROUTES_INPUT_SHOW_ROUTE'))
            else:
                signal = 'error'
                flash(
                    f"Serial Number, {serial_number}, is not in the database. Please add the inventory first.")

    return render_template(
        "fw_routes_input_show_route.html",
        form=form,
        signal=signal
    )


# Firewall Interfaces - Text Input
@app.route("/firewall/asa/interfaces/input/run_config_interfaces", methods=['GET', 'POST'],)
def FIREWALL_INTERFACES_INPUT_RUN_CONFIG_INTERFACES():
    serial_number = None
    input_txt = None

    interface_name = None
    interface_ip = None
    interface_subnet = None
    interface_zone = None
    interface_description = None
    interface_vlan = None
    state = None

    signal = None
    form = FIREWALL_INTERFACE_INPUT_RUN_CONFIG_INTERFACES_FORM()

    if request.method == 'POST':
        if form.validate_on_submit():
            serial_number = form.fm_serial_number.data
            input_txt = form.fm_input_txt.data
            inventory = FIREWALL_INVENTORY_TABLE.query.filter_by(
                db_serial_number=serial_number).first()
            if inventory is not None:
                print("----------------------")
                print("RAW STRING")
                print("----------------------")
                print(input_txt)

                iface_count = 0
                ifaces = input_txt.split('!')
                for iface in ifaces:

                    double_dot_dec_pattern = re.compile(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
                    result_filter = double_dot_dec_pattern.search(iface)

                    if result_filter:
                        print(f'Interface[{iface_count}]: {iface}')
                        iface_count += 1

                        row_count = 0
                        rows = iface.split('\n')

                        for row in rows:

                            if "interface" in row:
                                print(
                                    f'Word, Interface, in Row[{row_count}]: {row}')
                                row_count += 1

                                cols = row.split(' ')
                                col_count = 0

                                for col in cols:
                                    print(f'Column[{col_count}]: {col}')
                                    col_count += 1

                                    if "interface" not in col:
                                        print(
                                            f'Word, interface, not in Column[{col_count}]: {col}')
                                        interface_name = col
                                        print(
                                            f"interface name is mapped to: {interface_name}")

                            if "ip address" in row:
                                print(
                                    f'Word, ip address, in Row[{row_count}]: {row}')
                                row_count += 1

                                cols = row.split(' ')
                                col_count = 0

                                for col in cols:
                                    print(f'Column[{col_count}]: {col}')

                                    dot_dec_pattern = re.compile(
                                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
                                    result_filter = dot_dec_pattern.search(col)

                                    if result_filter:
                                        if col.startswith('255'):
                                            print(
                                                f'The subnet is, {col}, at position Column[{col_count}]')
                                            interface_subnet = col
                                        else:
                                            print(
                                                f'The IPv4 Address is, {col}, at position Column[{col_count}]')
                                            interface_ip = col

                                    col_count += 1

                            if "description" in row:
                                print(
                                    f'Word, description, in Row[{row_count}]: {row}')
                                row_count += 1

                                cols = row.split(' ')
                                col_count = 0

                                for col in cols:
                                    print(f'Column[{col_count}]: {col}')
                                    col_count += 1

                                    if 'description' not in col:
                                        print(
                                            f'The interface description is, {col}')
                                        interface_description = col

                            if "nameif" in row:
                                print(
                                    f'Word, nameif, in Row[{row_count}]: {row}')
                                row_count += 1

                                cols = row.split(' ')
                                col_count = 0

                                for col in cols:
                                    print(f'Column[{col_count}]: {col}')
                                    col_count += 1

                                    if 'nameif' not in col:
                                        print(
                                            f'The interface zone has been mapped too, {col}')
                                        interface_zone = col

                            if "vlan" in row:
                                print(
                                    f'Word, vlan, in Row[{row_count}]: {row}')
                                row_count += 1

                                cols = row.split(' ')
                                col_count = 0

                                for col in cols:
                                    print(f'Column[{col_count}]: {col}')
                                    col_count += 1

                                    if 'vlan' not in col:
                                        print(
                                            f'The interface vlan has been mapped too, {col}')
                                        interface_vlan = col

                        fw_int = FIREWALL_INTERFACES_TABLE.query.filter_by(
                            db_serial_number=serial_number, db_interface_name=interface_name).first()

                        if interface_description is None:
                            interface_description = 'empty'

                        if interface_zone is None:
                            interface_zone = 'empty'

                        if interface_vlan is None:
                            interface_vlan = 'empty'

                        if state is None:
                            state = 'new'

                        if fw_int is None:
                            entry = FIREWALL_INTERFACES_TABLE(
                                db_interface_name=interface_name,
                                db_interface_ip=interface_ip,
                                db_interface_subnet=interface_subnet,
                                db_interface_zone=interface_zone,
                                db_interface_vlan=interface_vlan,
                                db_interface_description=interface_description,
                                db_serial_number=serial_number,
                                db_state=state
                            )
                            db.session.add(entry)
                            db.session.commit()
                            sleep(1)
                            signal = 'info'
                            flash(
                                f'New interface, {interface_name}, for firewall, {serial_number}, has been successfully added to database!')

                        else:
                            if interface_ip != '':
                                fw_int.db_interface_ip = interface_ip
                                db.session.commit()
                                signal = 'info'
                                flash(
                                    f"IP address, {interface_ip}, for firewall, {serial_number}, interface {interface_name} has been updated")
                                fw_int.db_state = 'updated'
                                db.session.commit()
                            if interface_subnet != '':
                                fw_int.db_interface_subnet = interface_subnet
                                db.session.commit()
                                signal = 'info'
                                flash(
                                    f"Subnet, {interface_subnet}, for firewall, {serial_number}, interface {interface_name} has been updated")
                                fw_int.db_state = 'updated'
                                db.session.commit()
                            if interface_description != '':
                                fw_int.db_interface_description = interface_description
                                db.session.commit()
                                signal = 'info'
                                flash(
                                    f"Description, {interface_description}, for firewall, {serial_number}, interface {interface_name} has been updated")
                                fw_int.db_state = 'updated'
                                db.session.commit()
                            if interface_zone != '':
                                fw_int.db_interface_zone = interface_zone
                                db.session.commit()
                                signal = 'info'
                                flash(
                                    f"Security Zone, {interface_zone}, for firewall, {serial_number}, interface {interface_name} has been updated")
                                fw_int.db_state = 'updated'
                                db.session.commit()
                            if interface_vlan != '':
                                fw_int.db_interface_vlan = interface_vlan
                                db.session.commit()
                                signal = 'info'
                                flash(
                                    f"VLAN, {interface_vlan}, for firewall, {serial_number}, interface {interface_name} has been updated")
                                fw_int.db_state = 'updated'
                                db.session.commit()
        return redirect(url_for('FIREWALL_INTERFACES_INPUT_RUN_CONFIG_INTERFACES'))

    return render_template(
        "fw_interfaces_input_run_config_interfaces.html",
        form=form,
        signal=signal
    )


########################
### START WEB SERVER ###
########################
if __name__ == "__main__":
    app.run(debug=True)
