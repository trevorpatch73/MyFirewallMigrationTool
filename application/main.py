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
    db_source_zone = db.Column(db.String(300), nullable=True)
    db_destination_ip = db.Column(db.String(20), primary_key=True)
    db_destination_zone = db.Column(db.String(300), nullable=True)
    db_protocol = db.Column(db.String(5), primary_key=True)
    db_port_number = db.Column(db.String(7), primary_key=True)
    db_rule_name = db.Column(db.String(300), nullable=True)
    db_state = db.Column(db.String(50), nullable=True)

    db_serial_number = db.Column(db.String, db.ForeignKey(
        'FIREWALL_INVENTORY_TABLE.db_serial_number'),  primary_key=True, nullable=False)


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
@app.route("/firewall/rules/input/show-access-list", methods=['GET', 'POST'],)
def FIREWALL_RULES_TEXT():
    serial_number = None
    input_txt = None

    source_ip = None
    destination_ip = None
    protocol = None
    port_number = None
    rule_name = None
    state = None

    signal = None
    form = FIREWALL_RULES_TEXT_FORM()

    if request.method == 'POST':
        if form.validate_on_submit():
            serial_number = form.fm_serial_number.data
            input_txt = form.fm_input_txt.data
            inventory = FIREWALL_INVENTORY_TABLE.query.filter_by(
                db_serial_number=serial_number).first()

    return render_template(
        "fw_rules_input_show_access_list.html",
        form=form,
        signal=signal
    )


# Firewall NATs - Text Input
@app.route("/firewall/nats/text", methods=['GET', 'POST'],)
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
@app.route("/firewall/routes/input/show_routes", methods=['GET', 'POST'],)
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
    form = FIREWALL_ROUTES_INPUT_SHOW_ROUTE()

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

                return redirect(url_for('FIREWALL_ROUTES_TEXT'))
            else:
                signal = 'error'
                flash(
                    f"Serial Number, {serial_number}, is not in the database. Please add the inventory first.")

    return render_template(
        "fw_routes_text.html",
        form=form,
        signal=signal
    )


# Firewall Interfaces - Text Input
@app.route("/firewall/interfaces/input/run_config_interfaces", methods=['GET', 'POST'],)
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
                            return redirect(url_for('FIREWALL_INTERFACES_INPUT_RUN_CONFIG_INTERFACES'))

                        else:
                            if interface_ip != '':
                                fw_int.db_interface_ip = interface_ip
                                db.session.commit()
                                signal = 'info'
                                flash(
                                    f"IP address, {interface_ip}, for firewall, {serial_number}, interface {interface_name} has been updated")
                                fw_int.db_state = 'updated'
                                db.session.com
                            if interface_subnet != '':
                                fw_int.db_interface_subnet = interface_subnet
                                db.session.commit()
                                signal = 'info'
                                flash(
                                    f"Subnet, {interface_subnet}, for firewall, {serial_number}, interface {interface_name} has been updated")
                                fw_int.db_state = 'updated'
                                db.session.com
                            if interface_description != '':
                                fw_int.db_interface_description = interface_description
                                db.session.commit()
                                signal = 'info'
                                flash(
                                    f"Description, {interface_description}, for firewall, {serial_number}, interface {interface_name} has been updated")
                                fw_int.db_state = 'updated'
                                db.session.com
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
