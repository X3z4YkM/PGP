from classes.pgp import *
from modules.modules import clear_terminal
from classes.user import User
from modules import constants
import time
import os
from Crypto.PublicKey import RSA, DSA, ElGamal


def main():
    print("=======================__PGP__===========================")
    print("=========================================================")
    pp = pprint.PrettyPrinter(depth=4)
    name = input("Enter your name\n>: ")
    email = input("Enter your email\n>: ")
    user = User(name, email)
    key_password = "GavriloNub"

    key = DSA.generate(1024)
    elg = ElGamal.generate()

    user.generate_key_pair(1, 1024, key_password)
    user.generate_key_pair(2, 1024, key_password)

    key_id_hex_string0 = hex(int.from_bytes(user.private_key_chain[0]["key_id"], byteorder='big'))
    key_id_hex_string1 = hex(int.from_bytes(user.private_key_chain[1]["key_id"], byteorder='big'))
    # user.export_private_key(f'./private/{user.name}/keys/{user.email}_{key_id_hex_string0}.pem', user.private_key_chain[0]["key_id"])
    # user.import_private_key(f'./private/{user.name}/keys/{user.email}_{key_id_hex_string0}.pem', key_password)
    # user.export_private_key(f'./private/{user.name}/keys/{user.email}_{key_id_hex_string1}.pem', user.private_key_chain[1]["key_id"])
    # user.import_private_key(f'./private/{user.name}/keys/{user.email}_{key_id_hex_string1}.pem', key_password)

    user.export_public_key(f'./public/{user.name}/keys/{user.email}_{key_id_hex_string0}.pem', user.private_key_chain[0]["key_id"])
    user.import_public_key(f'./public/{user.name}/keys/{user.email}_{key_id_hex_string0}.pem')
    user.export_public_key(f'./public/{user.name}/keys/{user.email}_{key_id_hex_string1}.pem', user.private_key_chain[1]["key_id"])
    user.import_public_key(f'./public/{user.name}/keys/{user.email}_{key_id_hex_string1}.pem')

    pp.pprint(user.private_key_chain)

    message = b"Neka pristojna poruka za testiranje, ne znam kako cu prevodioce da polozim jebo me fakultet nezavrseni"

    result = construct_message("Poruka", message, time.time(), key_password, user.private_key_chain[1],
                               user.public_key_chain[1], constants.ALGORITHM_AES, use_signature=True, use_zip=False,
                               use_radix64=False)
    print(result)
    extracted = extract_and_validate_message(result, user)
    pp.pprint(extracted)

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
