from modules.modules import clear_terminal
from classes.user import User


def main():
    print("=======================__PGP__===========================")
    print("=========================================================")
    name = input("Enter your name\n>: ")
    email = input("Enter your email\n>: ")
    algorithm = int(
        input("Select algorithm:\n1)RSA encryption/signature\n2)DES signature and ElGamal encryption\n>: ")) % 2
    key_size = int(input("Enter key size (1024 or 2048)\n>: "))
    while key_size != 1024 and key_size != 2048:
        key_size = int(input("Enter key size (1024 or 2048)\n>: "))
    key_password = input("Enter password for private key\n>: ")
    user = User(name, email, algorithm, key_size, key_password)

    state = 1
    while state != 0:

        clear_terminal()
        print("***User Interface***\n1)see info\n2)generate key pair\n"
              + "3)export keys\n4)import keys\n5)see all key pairs\n6)send a message\n0)exit")
        state = int(input(">: "))
        if state == 1:
            print(user.get_info())
        if state == 2:
            private_key, public_key = user.generate_key_pair()
            print("key pair successfully generated ...")
        if state == 5:
            user.show_key_chain(password_in=input("[ENTER PASSWORD] >:"))


if __name__ == '__main__':
    main()
