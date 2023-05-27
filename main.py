from classes.mailbox import MailBox
from classes.pgp import *
from modules.modules import clear_terminal
from classes.user import User
from modules import constants
import time
import os
from Cryptodome.PublicKey import ElGamal
from Crypto.PublicKey import RSA, DSA, ElGamal

mailboxAgent = MailBox()


def main():
    print("=======================__PGP__===========================")
    print("=========================================================")
    name = input("Enter your name\n>: ")
    email = input("Enter your email\n>: ")
    user = User(name, email)

    user.generate_key_pair()

    message = b"Neka pristojna poruka za testiranje, ne znam kako cu prevodioce da polozim jebo me fakultet nezavrseni me jebo"
    signing_key = RSA.generate(2048)
    encryption_key = RSA.generate(2048)
    result = construct_message("Poruka", message, time.time(), constants.SIGN_ENC_RSA, signing_key, encryption_key,
                               constants.ALGORITHM_NONE, use_signature=False, use_zip=True, use_radix64=True)
    print(result)
    extract_and_validate_message(result, user)


    state = 1
    while state != 0:
        clear_terminal()
        print("***User Interface***\n1)see info\n2)generate key pair\n"
              + "3)export keys\n4)import keys\n5)see all key pairs\n6)send a message\n0)exit")
        state = int(input(">: "))
        if state == 1:
            print(user.get_info())
        if state == 2:
            algorithm = int(
                input("Select algorithm:\n1)RSA encryption/signature\n2)DES signature and ElGamal encryption\n>: "))
            key_size = int(input("Enter key size (1024 or 2048)\n>: "))

            while key_size != 1024 and key_size != 2048:
                key_size = int(input("Enter key size (1024 or 2048)\n>: "))

            key_password = input("Enter password for private key\n>: ")
            user.generate_key_pair(algorithm, key_size, key_password)
            print("key pair successfully generated ...")
        if state == 3:
            user.export_private_key(path=f'./private/{user.name}/keys/')
        if state == 4:
            user.import_private_key(f'./private/{user.name}/keys/file.pem')
        if state == 5:
            user.show_key_chain(password_in=input("[ENTER PASSWORD] >:"))
        if state == 6:
            pass


if __name__ == '__main__':
    main()
