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

    message = b"Neka pristojna poruka za testiranje, ne znam kako cu prevodioce da polozim jebo me fakultet nezavrseni me jebo"
    signing_key = RSA.generate(2048)
    encryption_key = RSA.generate(2048)
    print(construct_message("Poruka", message, time.time(), constants.SIGN_ENC_RSA, signing_key, encryption_key,
                            constants.ALGORYTHM_NONE, use_signature=True, use_zip=True, use_radix64=False))

    state = 1
    while state != 0:
        clear_terminal()
        print("***User Interface***\n1)see info\n2)generate key pair\n"
              + "3)export keys\n4)import keys\n5)see all key pairs\n6)send a message\n0)exit")
        state = int(input(">: "))
        if state == 1:
            print(user.get_info())
        if state == 2:
            user.generate_key_pair()
            print("key pair successfully generated ...")
        if state == 3:
            user.export_private_key(path=f'./private/{user.name}/keys/')
        if state == 4:
            user.import_private_key(f'./private/{user.name}/keys/file.pem')
        if state == 5:
            user.show_key_chain(password_in=input("[ENTER PASSWORD] >:"))
        if state == 6:
            print(construct_message("filename", b"message poruka cao cao cao", time.time(),
                                    constants.SIGN_ENC_DSA_ELGAMAL, keyDes, public_key,
                                    "session_algorythm", b"1234567890123456", True, True))


if __name__ == '__main__':
    main()
