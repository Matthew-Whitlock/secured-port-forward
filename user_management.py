#!/usr/bin/python3
from passlib.hash import bcrypt_sha256 as bcrypt
import json
import threading;
from copy import deepcopy

class UserDB:
    def __init__(self, db_filename = "users.json", rounds = bcrypt.default_rounds, lazy_db_write = False, allow_insecure = False):
        
        self.db_filename = db_filename;
        self.rounds = rounds;
        self.lazy_db_write = lazy_db_write;
        self.allow_insecure = allow_insecure;

        self.lock = threading.Lock();

        try:
            with open(self.db_filename, 'r') as db_file:
                self.db = json.load(db_file)
            self.db_loaded = True;
        except:
            print("UserDB Warning: Database file could not be loaded.\nWill overwrite database on any write operations.\nCheck self.db_loaded to confirm database is properly loaded if you expect it to be.");
            self.db = {};
            self.db_loaded = False;

    def write_pass(self, username: str, password: str, salt = None):
        hasher = bcrypt.using(rounds=self.rounds);
        if salt:
            hasher = hasher.using(salt=salt);
        
        hashed_password_info = hasher.hash(password);
        
        user = self.db.get(username, None);
        if user is None:
            self.db[username] = {};
            user = self.db.get(username)
        user["password_info"] = hashed_password_info;

        if not self.lazy_db_write:
            self.write_db();

    def has_user(self, username):
        user = self.db.get(username, None)
        return user != None

    def get_user_value(self, username, key):
        return deepcopy(self.db.get(username, {}).get(key, None))
        
    #Return user dict if login successful, else None
    def login(self, username: str, password: str):
       user = self.db.get(username, None);
       if user is None:
           return None;

       password_info = user.get("password_info", None)
       if password_info is None:
           if self.allow_insecure:
               return user;
           return None;

       if bcrypt.verify(password, password_info):
           return user
       return None
    
    def write_db(self):
        with self.lock:
            with open(self.db_filename, 'w') as db_file:
                json.dump(self.db, db_file);
