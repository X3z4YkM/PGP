from Crypto.PublicKey import RSA

from user_class.user import User


def main():
    print("----------------------\n\tPGP\t\n----------------------")
    name = input("Enter your name >: ")
    email = input("Enter your email >: ")
    algorithm = input("Select algorithm:\n1)RSA encryption/description\n2)DES signature and ElGamal encryption\n>: ")
    key_size = input("Enter key size >: ")
    key_password = input("Enter password for private key >: ")
    user = User(name, email, algorithm, key_size, key_password)
    print(user.get_info())
    

if __name__ == '__main__':
    main()
