from datetime import datetime
from Crypto.IO import PEM
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, DSA, ElGamal
from modules.modules import get_current_time, create_path
import itertools
from Cryptodome.Cipher import CAST
import re
from Cryptodome.Util.Padding import unpad

public_key_chain = []

class User:
    _ids = itertools.count(0)

    def __init__(self, name, email):
        self.id = next(self._ids)
        self.name = name
        self.email = email
        self.local_keychain = []

    def get_info(self):
        return f"[Name]: {self.name}\n[Email]: {self.email}\n"

    def verified_user_password(self, password_en, password_in):
        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        has_pass = sha1_hash.digest()[:16]

        return password_en == has_pass

    def generate_key_pair(self, algorithm, key_size, key_password):
        try:
            sha1_hash = SHA1.new()
            sha1_hash.update(key_password.encode('utf-8'))
            key_password = sha1_hash.digest()[:16]
            private_key = None
            public_key = None

            if algorithm == 'RSA':
                # gen rsa private and public key and save them into a .pem file
                key = RSA.generate(key_size)
                private_key = key.export_key(format='PEM')
                public_key = key.publickey().export_key(format='PEM')

            elif algorithm == 'DSA/Elgamal':
                # gen dsa key pair
                keyDsa = DSA.generate(key_size)
                private_key = keyDsa.export_key(format='PEM')
                public_key = keyDsa.public_key().export_key(format='PEM')

            key_id_temp = int.from_bytes(public_key, byteorder='big')
            key_ID = key_id_temp & ((1 << 64) - 1)
            cast128_object = CAST.new(key_password, CAST.MODE_ECB)
            padded_key = private_key.rjust(8 * ((len(private_key) + 7) // 8))
            encrypted_PR_key = cast128_object.encrypt(padded_key)
            self.local_keychain.append({
                "private_key": encrypted_PR_key,
                "public_key": public_key,
                "password": key_password,
                "key_id": key_ID,
                "time_stamp": get_current_time(),
                "user_id": self.email
            })

            public_key_chain.append({
                "public_key": public_key,
                "user_id": self.id,
                "key_id": key_ID,
                "time_stamp": get_current_time()
            })
        except ValueError as error:
            raise error

    def import_key_from_file_alter(self, path):
        print("[IMPORT STARTED] ...")
        file = open(path, 'rb')
        key = file.read()
        file.close()
        key_data = key.split(b"****NEWKEY****")[:-1]
        for key_piece in key_data:
            time_of_creation, key_id, public_key, encrypted_pr_key, user_id = key_piece.split(b"*--*")
            time_of_creation = datetime.fromisoformat(time_of_creation.decode())
            key_id = int(key_id.decode())
            user_id = str(user_id.decode())

            # decrypt the key - ask use for password for the private keys
            key_password = input("[ENTER PASSWORD] >: ")

            """
            First we make a SHA1 object for hashing the given password
            then we take the least 16 bytes of the hashed value
            then we use CAST-128 to decrypt the key
            """

            sha1_hash = SHA1.new()
            sha1_hash.update(key_password.encode())
            key_password = sha1_hash.digest()[:16]
            cast128_object = CAST.new(key_password, CAST.MODE_ECB)
            private_key_decrypted = cast128_object.decrypt(encrypted_pr_key)

            self.local_keychain.append({
                "private_key": private_key_decrypted,
                "public_key": public_key,
                "public_key_info": {
                    "time_of_creation": time_of_creation,
                    "key_id": key_id,
                    "owner_trust": True,
                    "user_id": self.id
                },
                "private_key_info": {
                    "time_of_creation": time_of_creation,
                    "key_id": key_id,
                    "public_key": public_key,
                    "encrypted_pr_key": None,
                    "user_id": user_id
                },
                "password": key_password
            })
        print("[IMPORTED KEY] ...")

    def export_key_to_file_alter(self, local_key_chain, path):
        pem_data = b""
        """ 
        We take every pair public/private keys and create a private keychain for exporting
        !!This method will be renamed to south the specific purpose of creating private keychain!!  
        """
        for pair in local_key_chain:
            pem_data += (pair.get("private_key_info").get("time_of_creation").isoformat().encode('utf-16') + b"*--*"
                         + str(pair.get("private_key_info").get("key_id")).encode('utf-16') + b"*--*"
                         + pair.get("private_key_info").get("public_key") + b"*--*"
                         + pair.get("private_key_info").get("encrypted_pr_key") + b"*--*"
                         + str(pair.get("private_key_info").get("user_id")).encode('utf-16') + b"****NEWKEY****")
        print("[EXPORT STARTED] ...")
        file_path = create_path(path)
        file = open(file_path, 'wb')
        file.write(pem_data)
        file.close()
        print("[EXPORTED KEY] ...")

    def import_private_key(self, path, key_password):
        try:
            file = open(path, 'rb')
            key = file.read()
            file.close()
        except OSError as error:
            raise error
            return

        try:
            sha1_hash = SHA1.new()
            sha1_hash.update(key_password.encode('utf-8'))
            key_password = sha1_hash.digest()[:16]
            cast128_object = CAST.new(key_password, CAST.MODE_ECB)
            decrypted_key = cast128_object.decrypt(key)
            decrypted_key = decrypted_key.replace(b' ', b'', 2)
        except ValueError as error:
            raise ValueError("[ERROR INCORRECT PASSWORD]")
            return
        try:
            print("[IMPORT STARTED] ...")
            if self.check_rsa_key_header_private(decrypted_key):
                public_key = RSA.import_key(decrypted_key).public_key().export_key(format='PEM')
                key_id_temp = int.from_bytes(public_key, byteorder='big')
                key_ID = key_id_temp & ((1 << 64) - 1)
            else:
                public_key = DSA.import_key(key).public_key().export_key(format='PEM')
                key_id_temp = int.from_bytes(public_key, byteorder='big')
                key_ID = key_id_temp & ((1 << 64) - 1)

            self.local_keychain.append({
                "private_key": key,
                "public_key": public_key,
                "password": key_password,
                "key_id": key_ID,
                "time_stamp": get_current_time(),
                "user_id": self.email
            })
            print("[IMPORTED KEY] ...")
        except ValueError as error:
            raise error
            return

    def export_private_key(self, path, key_id=None, key_password=""):
        if not path or key_id is None:
            return print("[MISSING PARAMETERS]")

        try:
            for elem in self.local_keychain:
                 if elem.get("key_id") == key_id:
                    encrypted_pr_key = elem.get("private_key")
                    sha1_hash = SHA1.new()
                    sha1_hash.update(key_password.encode('utf-8'))
                    key_password_hashed = sha1_hash.digest()[:16]

                    if key_password_hashed != elem.get("password"):
                        raise ValueError("[ERROR INCORRECT PASSWORD]")

                    print("[EXPORT STARTED] ...")

                    file_path = create_path(path)
                    file = open(file_path, 'wb')
                    file.write(encrypted_pr_key)
                    file.close()

                    print("[EXPORTED KEY] ...")

                    return
            print("[ERROR KEY WASN'T FOUND]")
        except ValueError as e:
            print(str(e))

    def import_public_key(self, path):
        print("[IMPORTING PUBLIC KEY]")
        file = open(path, 'rb')
        key = file.read()
        file.close()

        print("[IMPORTED PUBLIC KEY]")
        if self.check_rsa_key_header_public(key):
            public_key = RSA.import_key(key).export_key(format='PEM')
        else:
            public_key = DSA.import_key(key).export_key(format='PEM')

        key_id_temp = int.from_bytes(public_key, byteorder='big')
        key_ID = key_id_temp & ((1 << 64) - 1)
        public_key_chain.append({
            "public_key": public_key,
            "user_id": self.id,
            "key_id": key_ID,
            "time_stamp": get_current_time()
        })

    def export_public_key(self, path, key_id=None):
        for key in self.local_keychain:
            if key.get('key_id') == key_id:
                print("[EXPORT STARTED] ...")
                file_path = create_path(path)
                file = open(file_path, 'wb')
                file.write(key.get("public_key"))
                file.close()
                print("[EXPORTED KEY] ...")
                break
        print("[ERROR KEY WASN'T FOUND]")

    def check_rsa_key_header_private(self, key_data):
        key_str = key_data.decode('utf-8')
        pattern = r'^.*-----BEGIN RSA PRIVATE KEY-----'
        return re.match(pattern, key_str)

    def check_rsa_key_header_public(self, key_data):
        key_str = key_data.decode('utf-8')
        pattern = r'^.*-----BEGIN RSA PUBLIC KEY-----'
        return re.match(pattern, key_str)

    def check_heder(self, key_data):
        key_str = key_data.decode('utf-8')
        pattern1 = r'^.*-----BEGIN RSA PRIVATE'
        pattern2 =  r'^.*-----BEGIN PRIVATE'
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
        if not self.local_keychain:
            return tem_arr

        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        for pair in self.local_keychain:
            try:
                decrypted_key = cast128_object.decrypt(pair.get("private_key"))
                decrypted_key = decrypted_key.replace(b' ', b'', 2)
                if self.check_heder(decrypted_key):
                    tem_arr.append({'private_key': decrypted_key, 'public_key': pair.get('public_key')})
            except ValueError:
                pass
        return tem_arr

    def get_private_keys(self, password_in):
        tem_arr = []
        if not self.local_keychain:
            return tem_arr

        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        for pair in self.local_keychain:
            try:
                decrypted_key = cast128_object.decrypt(pair.get("private_key"))
                decrypted_key = decrypted_key.replace(b' ', b'', 2)
                if self.check_heder(decrypted_key):
                    tem_arr.append({'key': decrypted_key, 'id': pair.get('key_id')})
            except ValueError:
                pass
        return tem_arr

    def get_my_public_keys(self, password_in):
        tem_arr = []
        if not self.local_keychain:
            return tem_arr

        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        for pair in self.local_keychain:
            try:
                decrypted_key = cast128_object.decrypt(pair.get("private_key"))
                decrypted_key = decrypted_key.replace(b' ', b'', 2)
                if self.check_heder(decrypted_key):
                    tem_arr.append({'key': pair.get('public_key'), 'id': pair.get('key_id')})
            except ValueError:
                pass
        return tem_arr

    def get_by_header(self, filter, password_in):
        tem_arr = []
        if not self.local_keychain:
            return tem_arr

        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        key_password = sha1_hash.digest()[:16]
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)
        for pair in self.local_keychain:
            try:
                decrypted_key = cast128_object.decrypt(pair.get("private_key"))
                decrypted_key = decrypted_key.replace(b' ', b'', 2)
                if self.check_filter_heder(decrypted_key, filter):
                    tem_arr.append({'key': decrypted_key, 'id': pair.get('key_id')})
            except ValueError:
                pass
        return tem_arr

    def get_public_key_chain(self):
        temp_arr = []
        for pair in public_key_chain:
            temp_arr.append(pair.get('public_key'))
        return temp_arr

    def get_public_key_chain_alt(self):
        temp_arr = []
        for pair in public_key_chain:
            temp_arr.append({'public_key': pair.get('public_key'), 'key_id':pair.get('key_id')})
        return temp_arr

    def search_public_key(self, key_id):
        for key in public_key_chain:
            if key.get("key_id") == key_id:
                return key

    def search_private_key(self, key_id):
        """This method returns unencrypted private key"""
        for key in self.local_keychain:
            if key.get("key_id") == key_id:
                return key
