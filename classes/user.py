from datetime import datetime

from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, DSA, ElGamal
from modules.modules import get_current_time, create_path
import itertools
from collections import defaultdict
from Cryptodome.Cipher import CAST



class User:
    _ids = itertools.count(0)

    def __init__(self, name, email):
        self.id = next(self._ids)
        self.name = name
        self.email = email
        self.local_keychain = []

    def get_info(self):
        return {"name": self.name,
                "email": self.email}

    def verified_user_password(self, password_en, password_in):
        sha1_hash = SHA1.new()
        sha1_hash.update(password_in.encode('utf-8'))
        has_pass = sha1_hash.digest()[:16]

        return password_en == has_pass

    def generate_key_pair(self):
        algorithm = int(
            input("Select algorithm:\n1)RSA encryption/signature\n2)DES signature and ElGamal encryption\n>: "))
        key_size = int(input("Enter key size (1024 or 2048)\n>: "))

        while key_size != 1024 and key_size != 2048:
            key_size = int(input("Enter key size (1024 or 2048)\n>: "))

        key_password = input("Enter password for private key\n>: ")
        sha1_hash = SHA1.new()
        sha1_hash.update(key_password.encode('utf-8'))
        key_password = sha1_hash.digest()[:16]
        private_key = None
        public_key = None

        if algorithm == 1:
            # get rsa private and public key and save them into a .pem file
            key = RSA.generate(key_size)
            private_key = key.export_key(format='PEM', passphrase=key_password)
            private_key = key.export_key(format='PEM', passphrase=key_password)
            public_key = key.publickey().export_key(format='PEM')
            self.PR_key_pass_dic[key_password].append(private_key)

        elif algorithm == 2:
            # get dsa private key and elgamal public key pair
            keyDsa = DSA.generate(key_size)
            keyElGamal = ElGamal.generate(key_size, get_random_bytes)
            private_key = keyDsa.export_key(format='PEM', passphrase=key_password)
            public_key = keyElGamal.publickey()
            self.PR_key_pass_dic[key_password].append(private_key)

        # now we format for the key_chain so that we can export theam
        """
            key_chain public
            ===============================================================================================
            --time_stamp-Key_ID--Public_KEY--Owner_Trust--User_ID---Key_Legit--Signature--Signature_trust--
            |           |      |           |            |         |                |         |            |
            |           |      |           |            |         |                |         |            |
            ------------------------------------------------------------------------------------------------
            |           |      |           |            |         |                |         |            |
            |           |      |           |            |         |                |         |            |
            ===============================================================================================
        """

        PU_time_of_creation = get_current_time()  # get current time in format 2023-05-25 15:04:08
        key_to_int = int.from_bytes(public_key, byteorder='big')  # convert key to integer
        PU_key_ID = key_to_int & ((1 << 64) - 1)  # now we get the least significant 64 bits
        PU_owner_Trust = True
        PU_user_ID = self.id

        """
        key_chain private
        ============================================================
        --time_stamp--Key_ID--Public_Key--Encrypted_PR_key--User_D--
        |           |       |           |                 |        |
        |           |       |           |                 |        |
        ------------------------------------------------------------
        |           |       |           |                 |        |
        |           |       |           |                 |        |
        ============================================================
        """
        PR_time_of_creation = get_current_time()
        key_to_int = int.from_bytes(private_key, byteorder='big')  # convert key to integer
        PR_key_ID = key_to_int & ((1 << 64) - 1)  # now we get the least significant 64 bits
        cast128_object = CAST.new(key_password, CAST.MODE_ECB)

        # Pad the message to be a multiple of 8 bytes (block size of CAST-128)
        padded_key = private_key.rjust(8 * ((len(private_key) + 7) // 8))
        encrypted_PR_key = cast128_object.encrypt(padded_key)

        self.local_keychain.append({
            "private_key": private_key,
            "public_key": public_key,
            "public_key_info": {
                "time_of_creation": PU_time_of_creation,
                "key_id": PU_key_ID,
                "owner_trust": PU_owner_Trust,
                "user_id": PU_user_ID
            },
            "private_key_info": {
                "time_of_creation": PR_time_of_creation,
                "key_id": PR_key_ID,
                "public_key": public_key,
                "encrypted_pr_key": encrypted_PR_key,
                "user_id": self.email
            },
            "password": key_password
        })

    def import_key_from_file(self, path):
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
                    "user_id": user_id
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

    def export_key_to_file(self, local_key_chain, path):
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

    def show_key_chain(self, password_in):
        if not self.local_keychain:
            return print("[EMPTY LOCAL KEY CHAIN]")

        for pair in self.local_keychain:
            if self.verified_user_password(pair.get('password'), password_in):
                print(f"==============\n[PRIVATE KEY]{pair.get('private_key')}\n[PUBLIC KEY]{pair.get('public_key')}\n")

    def show_keychain_private(self, password_in):
        print(f"==============\n[PRIVATE KEY]\n")

        if not self.local_keychain:
            return print("[EMPTY LOCAL KEY CHAIN]")

        for index, pair in enumerate(self.local_keychain):
            if self.verified_user_password(pair.get('password'), password_in):
                print(f"{index}) {pair.get('private_key')}\n")
