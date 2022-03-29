#!/usr/bin/python3
from pywebio import *
from pywebio.input import input, input_group, PASSWORD, TEXT, actions
from pywebio.output import put_text, use_scope, remove, put_row, put_buttons, put_button, put_tabs, toast, style
from pywebio.platform import flask
from user_management import UserDB; 
import service_management
from functools import partial

userDB = UserDB("users.json");

def forward_port_for_ip(ip):
    for service in service_management.get_service_names():
        if service_management.user_has_service(session.local.username, service):
            service_management.add_service_forward(ip, service);

def unforward_port_for_ip(ip):
    for service in service_management.get_service_names():
        if service_management.user_has_service(session.local.username, service):
            service_management.rem_service_forward(ip, service);


def is_valid_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters"

def login(data):
    if data["action"] == "login":
        user = userDB.login(data["username"], data["password"])
        if user == None:
            return ("password", "Unrecognized username or password!")
        session.local.username = data["username"]
        session.local.user = user
    elif data["action"] == "register":
        print(data["username"])
        if userDB.has_user(data["username"]):
            return ("username", "Username already exists!");
        userDB.write_pass(data["username"], data["password"])
        user = userDB.login(data["username"], data["password"])
        if user == None:
            #Uhhhh...
            return ("username", "Error registering user. This is weird.")
        session.local.username = data["username"]
        session.local.user = user;

def request_service(service_name):
    service_management.request_service_for_user(session.local.username, service_name);
    toast("Sent request to server PC. For urgent access contact admin.");


def modify_ip_listing(ip, action):
    if action == "Delete":
        session.local.user["ips"].pop(ip);
        unforward_port_for_ip(ip);
    elif action == "Update":
        if ip == session.info.user_ip:
            return;
        session.local.user["ips"][session.info.user_ip] = session.local.user["ips"][ip];
        session.local.user["ips"].pop(ip)

        unforward_port_for_ip(ip);
        forward_port_for_ip(session.info.user_ip);
    else:
        print("Unknown action!")
    remove("user_data")
    put_user_data();


def register_ip():
    user_ips = session.local.user.get("ips", None);
    if user_ips == None:
        session.local.user["ips"] = {}
        user_ips = session.local.user["ips"];
    
    for ip in user_ips:
        if(user_ips[ip] == pin.pin.new_ip_name):
            toast("Location name taken!");
            return;

    print(session.local.username + " registering IP " + session.info.user_ip + " to " + pin.pin.new_ip_name);
    user_ips[session.info.user_ip] = pin.pin.new_ip_name
    userDB.write_db();
    forward_port_for_ip(session.info.user_ip);
    remove("user_data")
    put_user_data()


def put_user_data():
    with use_scope("user_data"):
        ip_list = [];
        for ip in session.local.user.get("ips", {}):
            ip_list.append(put_row([put_text(session.local.user["ips"][ip] + ": " + ip), put_buttons(['Update','Delete'], onclick=partial(modify_ip_listing, ip))]))
        if len(ip_list) == 0:
            ip_list.append(put_text("You have no IPs registered!"))

        if session.local.user.get("ips", {}).get(session.info.user_ip, None) == None:
            ip_list.append(put_row([pin.put_input("new_ip_name", type="text", placeholder="Location name (Home, Work, ...)"),put_button("Register IP to new location",onclick=register_ip)]))

        services_info = [];
        for service in service_management.get_service_names():
            if service_management.user_has_service(session.local.username, service):
                services_info.append(style(put_text(service), "color:green"));
            else:
                services_info.append(put_row([style(put_text(service), "color:red"),
                    put_button(label="Request", onclick=partial(request_service, service_name=service))]));
                

        put_tabs([{"title": "My IPs", "content": ip_list}, {"title":"My Services", "content": services_info}]);

def home():
    with use_scope("login_screen"):
        put_text("Hello! This IP is unrecognized by this resource. Please sign in and register this IP if you believe you should have access to this resource.");
    
        login_field = input_group("Login", [
            input(type=TEXT, name="username", placeholder="Username", required = True), 
            input(name="password", placeholder="Password", type=PASSWORD, required = True, validate=is_valid_password),
            actions(name="action", buttons=[{"label":"Login", "value":"login", "type":"submit"},
                    {"label":"Register", "value":"register", "type":"submit"}])],
            validate=login)
        remove()

    #Only here on successful login!
    #But just in case
    if (session.local.username == None) or (session.local.user == None):
        put_text("Error! Try reloading!");
        return; #Not really sure how this will work.

    
    put_text("Welcome " + session.local.username + "!")

    put_user_data();

    

if __name__ == '__main__':
    flask.start_server(home, port=8000, debug=True, ssl_context=("/home/mwhitlo/network-helpers/cert.pem", "/home/mwhitlo/network-helpers/privkey.pem"))
