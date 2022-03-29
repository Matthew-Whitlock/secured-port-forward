#!/usr/bin/python3
import json
import sys
from user_management import UserDB
from gi.repository import GLib, Notify
from functools import partial
from threading import Thread
import os

SERVICES_FILENAME="services.json"
CONFIG_FILENAME="config.json"
ALLOW_GNOME_NOTIFICATIONS=True

#req_notifs[user][service]["notif"] = notification obj
#req_notifs[user][service]["count"] = num times user has requested (while this notification sitting)
req_notifs = {};
def gtk_thread(notifs_dict):
    req_notifs = notifs_dict;
    GLib.MainLoop.new(None, False).run()

if ALLOW_GNOME_NOTIFICATIONS:
    Notify.init("Port-Forward Service Management")
    #Need a thread to run a gnome event loop
    gnome_thread = Thread(target=gtk_thread, args=(req_notifs, ), daemon = True)
    gnome_thread.start();
    

def __get_services():
    try:
        with open(SERVICES_FILENAME, "r") as services_file:
            return json.load(services_file)
    except:
        return {};
def __write_services(services):
    with open(SERVICES_FILENAME, "w") as services_file:
        json.dump(services, services_file)
def __get_interface():
    with open(CONFIG_FILENAME, "r") as config_file:
        return json.load(config_file)["interface"]

def get_service_names():
    return list(__get_services().keys());

def user_has_service(username, servicename, services=None):
    if services is None:
        services = __get_services();
    return username in services.get(servicename, {}).get("users", []);

def __add_port_forward(ip, src, dest, iface=None):
    if iface == None:
        iface = __get_interface();
    cmd = "sudo /home/mwhitlo/network-helpers/make_route.sh " + str(iface) + " " + str(src) + " " + str(dest) + " " + str(ip);
    print("Executing: " + cmd)
    os.system(cmd)
def __rem_port_forward(ip, src, dest, iface=None):
    if iface == None:
        iface = __get_interface();
    cmd = "sudo /home/mwhitlo/network-helpers/rm_route.sh " + str(iface) + " " + str(src) + " " + str(dest) + " " + str(ip)
    print("Executing: " + cmd)
    os.system(cmd);

def add_service_forward(ip, servicename):
    print("adding service to: " + ip)
    services = __get_services();
    __add_port_forward(ip, services[servicename]["src"], services[servicename]["dst"]);
def rem_service_forward(ip, servicename):
    print("remming service to: " + ip)
    services = __get_services();
    __rem_port_forward(ip, services[servicename]["src"], services[servicename]["dst"]);


def __add_service(servicename, from_port, to_port):
    services = __get_services();
    for name in services:
        if name == servicename:
            print("Service \"" + servicename + "\" already exists! Aborting!");
            return;
    services[servicename] = {};
    services[servicename]["src"] = from_port;
    services[servicename]["dst"] = to_port;
    services[servicename]["users"] = [];

    __write_services(services);

def __del_service(servicename):
    services = __get_services();
    services.pop(servicename)
    __write_services(services);

def __permit_service(username, servicename, force):
    print("Attempted permit service");
    services = __get_services()
    service = services.get(servicename, None);
    if service == None:
        print("No such service as \"" + servicename + "\". Aborting.");
        return;
    if username in service["users"]:
        print("User \"" + username + "\" already has access to \"" + servicename + "\".");
        return;
    
    userDB = UserDB();
    if not userDB.has_user(username) and not force:
        print("WARNING: User \"" + username + "\" does not exist yet! Adding services to an open username is a security vulnerability. Use '-f' to permit anyway");
        return;

    service["users"].append(username);
    __write_services(services)

    #Also update iptables rules as needed
    ips = userDB.get_user_value(username, "ips");
    if ips == None:
        return;
    
    iface = __get_interface();
    for ip in userDB.get_user_value(username, "ips"):
        __add_port_forward(ip, service["src"], service["dst"], iface);

    req_notifs.get(username, {}).pop(servicename);
    if len(req_notifs.get(username, {}).keys()) < 1:
        req_notifs.pop(username);


def __restrict_service(username, servicename, force):
    services = __get_services()
    service = services.get(servicename, None)
    if service == None:
        print("No such service as \"" + servicename + "\". Aborting.");
        return;
    if not username in service["users"]:
        print("User \"" + username + "\" already doesn't have access to \"" + servicename + "\".");
        return;
    
    userDB = UserDB();
    if not userDB.has_user(username) and not force:
        print("WARNING: User \"" + username + "\" does not exist! Would not know what forwarding rules to use. Use '-f' to permit anyway");
        return;
    
    service["users"].remove(username);
    __write_services(services);
    
    #Also update iptables rules as needed
    ips = userDB.get_user_value(username, "ips");
    if ips == None:
        return;

    iface = __get_interface()
    for ip in ips:
        __rem_port_forward(ip, service["src"], service["dst"], iface);

def __notif_handler(notif, action, user_data=None):
    __permit_service(user_data[0], user_data[1], False)

def request_service_for_user(username, service):
    summary = "\"" + username + "\" requests access to " + service;
    

    notif = req_notifs.get(username, {}).get(service, {}).get("notif", None);
    if not notif == None:
        req_notifs[username][service]["count"] += 1
        body = "They have requested " + str(req_notifs[username][service]["count"]) + " times."
        notif.update(summary, body)
        notif.clear_actions();
        notif.add_action("permit",
                "Permit",
                __notif_handler,
                (username, service) #function arguments, but I already embedded them w/ partial()
        )
        notif.show()
        return;


    body = "They have requested 1 time.";

    notif = Notify.Notification.new(summary, body)
    notif.add_action("permit",
            "Permit",
            __notif_handler,
            (username, service) #function arguments, but I already embedded them w/ partial()
    )
    
    #eww
    usr = req_notifs.get(username, None);
    if usr == None:
        req_notifs[username] = {}
        usr = req_notifs[username]
    srvc = usr.get(service, None);
    if srvc == None:
        usr[service] = {}
        srvc = usr[service]
    srvc["notif"] = notif
    srvc["count"] = 1

    notif.show();

def print_usage():
    print("Usage: " + sys.argv[0] + " <command> ... ");
    print("Commands:")
    print("  add\n    Add a new service, requires service name, src and dst ports.");
    print("  delete\n    Delete a service, requires service name");
    print("  permit\n    Give user access to service, requires service name and username");
    print("  restrict\n    Remove user's access to service, requires service name and username");
    print("-u <username>")
    print("-n <service name>")
    print("-s <source port>")
    print("-d <destination port>")
    print("-f forces permit/restrict to execute when username does not exist in users database");
    exit(1);


def print_flag_err(flag):
    print("Command " + sys.argv[1] + " requires flag " + flag)
    print("\n")
    print_usage();
    
def get_flag(flag):
    if not flag in sys.argv:
        print_flag_err(flag);

    idx = sys.argv.index(flag);
    if len(sys.argv) < idx + 2:
        print_flag_err(flag);

    val = sys.argv[idx+1];
    if val.startswith("-"):
        print_flag_err(flag);
    return val;

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage()

    cmd = str(sys.argv[1]);
    if cmd == "add":
        __add_service(get_flag("-n"), get_flag("-s"), get_flag("-d"))
    elif cmd == "delete":
        __del_service(get_flag("-n"));
    elif cmd == "permit":
        __permit_service(get_flag("-u"), get_flag("-n"), "-f" in sys.argv)
    elif cmd == "restrict":
        __restrict_service(get_flag("-u"), get_flag("-n"), "-f" in sys.argv)
    else:
        print_usage();

