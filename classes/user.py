from datetime import datetime
from tkinter import simpledialog

from Crypto.IO import PEM
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, DSA, ElGamal
from modules.modules import get_current_time, create_path
import itertools
from Cryptodome.Cipher import CAST
from Crypto.Util.Padding import pad, unpad
import re
from Cryptodome.Util.Padding import unpad


def check_rsa_key_header_private(key_data):
    key_str = key_data.decode('utf-8')
    pattern = r'^.*-----BEGIN RSA PRIVATE KEY-----'
    return re.match(pattern, key_str)


def check_rsa_key_header_public(key_data):
    key_str = key_data.decode('utf-8')
    pattern = r'^.*-----BEGIN RSA PUBLIC KEY-----'
    return re.match(pattern, key_str)


def check_dsa_key_header_private(key_data):
    key_str = key_data.decode('utf-8')
    pattern = r'^.*-----BEGIN PRIVATE KEY-----'
    return re.match(pattern, key_str)


def check_dsa_key_header_public(key_data):
    key_str = key_data.decode('utf-8')
    pattern = r'^.*-----BEGIN PUBLIC KEY-----'
    return re.match(pattern, key_str)


class User:
    _ids = itertools.count(0)

    def __init__(self, name, email):
        self.id = next(self._ids)
        self.name = name
        self.email = email
        self.private_key_chain = []
        self.public_key_chain = []

    def get_info(self):
        return f"[Name]: {self.name}\n[Email]: {self.email}\n"

    @staticmethod
    def encrypt_private_key(private_key, key_password):
        sha1_hash = SHA1.new()
        sha1_hash.update(key_password.encode())
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        return cast128_object.encrypt(pad(private_key, CAST.block_size))

    def generate_key_pair(self, algorithm, key_size, key_password):
        if algorithm == 'RSA':
            # gen rsa private and public key and save them into a .pem file
            key = RSA.generate(key_size)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

        elif algorithm == 'DSA/Elgamal':
            # gen dsa key pair
            key = DSA.generate(key_size)
            private_key = key.export_key()
            public_key = key.public_key().export_key()

        key_id = self.derive_key_id(public_key)
        encrypted_pr_key = self.encrypt_private_key(private_key, key_password)

        self.private_key_chain.append({
            "private_key": encrypted_pr_key,
            "public_key": public_key,
            "key_id": key_id,
            "time_stamp": get_current_time(),
            "user_id": self.email
        })

        self.public_key_chain.append({
            "public_key": public_key,
            "user_id": self.email,
            "key_id": key_id,
            "time_stamp": get_current_time(),
            "owner_email": self.email
        })
        return key

    @staticmethod
    def decrypt_private_key(encrypted_pr_key, key_password):
        sha1_hash = SHA1.new()
        sha1_hash.update(key_password.encode())
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        return unpad(cast128_object.decrypt(encrypted_pr_key), CAST.block_size)

    @staticmethod
    def derive_key_id(public_key):
        return SHA1.new(public_key).digest()[-8:]

    def import_private_key(self, path, key_password):
        print("[IMPORT STARTED] ...")
        with open(path, 'rb') as file:
            key_pem = file.read()

        decrypted_key = self.decrypt_private_key(key_pem, key_password)

        if check_rsa_key_header_private(decrypted_key):
            public_key = RSA.import_key(decrypted_key).public_key().export_key(format='PEM')
        elif check_dsa_key_header_private(decrypted_key):
            public_key = DSA.import_key(decrypted_key).public_key().export_key(format='PEM')
        else:
            raise ValueError("Invalid or unknown key PEM format!")
        key_id = self.derive_key_id(public_key)
        self.private_key_chain.append({
            "private_key": key_pem,
            "public_key": public_key,
            "password": key_password,
            "key_id": key_id,
            "time_stamp": get_current_time(),
            "user_id": self.email,
            "owner_name": self.name
        })

        self.public_key_chain.append({
            "public_key": public_key,
            "user_id": self.id,
            "key_id": key_id,
            "time_stamp": get_current_time(),
            "owner_email": self.email
        })
        print("[IMPORTED KEY] ...")

    def export_private_key(self, path, key_id=None, key_password=""):
        if not path or key_id is None:
            return print("[MISSING PARAMETERS]")
        try:
            elem = self.search_private_key(key_id)
            encrypted_pr_key = elem.get("private_key")
            print("[EXPORT STARTED] ...")
            create_path(path)
            with open(path, 'wb') as file:
                file.write(encrypted_pr_key)
            print("[EXPORTED KEY] ...")

        except ValueError as e:
            print(str(e))

    def import_public_key(self, path):
        print("[IMPORTING PUBLIC KEY]")
        with open(path, 'rb') as file:
            key = file.read()

        try:
            public_key = RSA.import_key(key).export_key(format='PEM')
        except ValueError:
            try:
                public_key = DSA.import_key(key).export_key(format='PEM')
            except ValueError:
                raise ValueError("Invalid or unknown key PEM format!")

        key_id = self.derive_key_id(public_key)
        owner_email = simpledialog.askstring("Input", f"Enter owner email for key_id:{key_id.hex()}: ")
        self.public_key_chain.append({
            "public_key": public_key,
            "user_id": self.id,
            "key_id": key_id,
            "time_stamp": get_current_time(),
            "owner_email": owner_email
        })
        print("[IMPORTED PUBLIC KEY]")

    def export_public_key(self, path, key_id=None):
        key = self.search_private_key(key_id)
        print("[EXPORT STARTED] ...")
        create_path(path)
        with open(path, 'wb') as file:
            file.write(key.get("public_key"))
        print("[EXPORTED KEY] ...")

    def check_heder(self, key_data):
        key_str = key_data.decode('utf-8')
        pattern1 = r'^.*-----BEGIN RSA PRIVATE'
        pattern2 = r'^.*-----BEGIN PRIVATE'
        return re.match(pattern1, key_str) or re.match(pattern2, key_str)

    def check_filter_heder(self, key_data, filter):
        if filter == 'RSA':
            key_str = key_data.decode('utf-8')
            pattern1 = r'^.*-----BEGIN RSA PRIVATE'
            return re.match(pattern1, key_str)
        else:
            key_str = key_data.decode('utf-8')
            pattern2 = r'^.*-----BEGIN PRIVATE'
            return re.match(pattern2, key_str)

    def show_key_chain(self, password_in):
        tem_arr = []
        if not self.private_key_chain:
            return tem_arr

        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        for pair in self.private_key_chain:
            try:
                decrypted_key = cast128_object.decrypt(pair.get("private_key"))
                if self.check_heder(decrypted_key):
                    tem_arr.append({'private_key': decrypted_key, 'public_key': pair.get('public_key')})
            except ValueError:
                pass
        return tem_arr

    def get_private_keys(self, password_in):
        tem_arr = []
        if not self.private_key_chain:
            return tem_arr

        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        for pair in self.private_key_chain:
            try:
                decrypted_key = cast128_object.decrypt(pair.get("private_key"))
                if self.check_heder(decrypted_key):
                    tem_arr.append({'key': decrypted_key, 'id': pair.get('key_id'), 'pair': pair})
            except ValueError:
                pass
        return tem_arr

    def get_my_public_keys(self, password_in):
        tem_arr = []
        if not self.private_key_chain:
            return tem_arr

        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        for pair in self.private_key_chain:
            try:
                decrypted_key = cast128_object.decrypt(pair.get("private_key"))
                if self.check_heder(decrypted_key):
                    tem_arr.append({'key': pair.get('public_key'), 'id': pair.get('key_id'), 'pair': pair})
            except ValueError:
                pass
        return tem_arr

    def get_by_header(self, filter, password_in):
        tem_arr = []
        if not self.private_key_chain:
            return tem_arr

        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        for pair in self.private_key_chain:
            try:
                decrypted_key = cast128_object.decrypt(pair.get("private_key"))
                if self.check_filter_heder(decrypted_key, filter):
                    tem_arr.append({'key': decrypted_key, 'id': pair.get('key_id'), 'pair': pair})
            except ValueError:
                pass
        return tem_arr

    def get_public_key_chain(self):
        temp_arr = []
        for pair in self.public_key_chain:
            temp_arr.append(pair)
        return temp_arr

    def get_public_key_chain_alt(self):
        temp_arr = []
        for pair in self.public_key_chain:
            temp_arr.append({'public_key': pair.get('public_key'), 'key_id': pair.get('key_id'), 'pair': pair})
        return temp_arr

    def show_keychain_private(self, password_in):
        print(f"==============\n[PRIVATE KEY]\n")

        if not self.private_key_chain:
            return print("[EMPTY LOCAL KEY CHAIN]")

        for index, pair in enumerate(self.private_key_chain):
            print(f"{index}) {pair.get('public_key')} {pair.get('private_key')}\n")

    def search_public_key(self, key_id):
        for key in self.public_key_chain:
            if key.get("key_id") == key_id:
                return key
        raise ValueError(f"No public key with id: {key_id.hex()}")

    def search_private_key(self, key_id):
        """This method returns encrypted private key"""

        for key in self.private_key_chain:
            if key.get("key_id") == key_id:
                return key
        raise ValueError(f"No private key with id: {key_id.hex()}")
