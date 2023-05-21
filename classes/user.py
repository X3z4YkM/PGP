from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

from Crypto.PublicKey import RSA, DSA, ElGamal


class User:
    def __init__(self, name, email, algo, key_size, key_pass):
        self.name = name
        self.email = email
        self.algorithm = algo
        self.key_size = key_size
        hasher = SHA256.new()
        hasher.update(key_pass.encode('utf-8'))
        self.key_password = hasher.hexdigest()
        self.my_keychain = []

    def get_info(self):
        return {"name": self.name,
                "email": self.email,
                "algorithm": self.algorithm,
                "key_size": self.key_size,
                "key_password": self.key_password}

    def verified_user_password(self, password_in):
        hasher = SHA256.new()
        hasher.update(password_in.encode('utf-8'))
        has_pass = hasher.hexdigest()
        return self.key_password == has_pass

    def generate_key_pair(self):
        if self.algorithm == 1:
            # get rsa private and public key and save them into a .pem file
            key = RSA.generate(self.key_size)
            private_key = key.export_key(format='PEM', passphrase=self.key_password)
            public_key = key.publickey().export_key(format='PEM')
            self.my_keychain.append({
                "private_key": private_key,
                "public_key": public_key
            })
            return private_key, public_key
        elif self.algorithm == 2:
            # get dsa private key and elgamal public key pair
            keyDes = DSA.generate(self.key_size)
            keyElGamal = ElGamal.generate(self.key_size, get_random_bytes)
            private_key = keyDes.export_key(format='PAM', passphrase=self.key_password)
            public_key = keyElGamal.publickey().export_key()
            self.my_keychain.append({
                "private_key": private_key,
                "public_key": public_key
            })
            return private_key, public_key

    def import_key_from_file(self, path):
        print("[IMPORT STARTED] ...")
        file = open(path, 'rb')
        key = file.read()
        file.close()
        print("[IMPORTED KEY] ...")
        return key

    def export_key_to_file(self, key, path):
        print("[EXPORT STARTED] ...")
        file = open(path, 'wb')
        file.write(key)
        file.close()
        print("[EXPORTED KEY] ...")

    def show_key_chain(self, password_in):

        if self.verified_user_password(password_in):
            for pair in self.my_keychain:
                print(f"==============\n[PRIVATE KEY]{pair.get('private_key')}\n[PUBLIC KEY]{pair.get('public_key')}\n")
        else:
            print("[ERROR] incorrect password")

    def show_keychain_private(self, password_in):
        pass
