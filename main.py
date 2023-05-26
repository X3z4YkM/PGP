from classes.mailbox import MailBox
from modules.modules import clear_terminal
from classes.user import User

mailboxAgent = MailBox()
def main():
    print("=======================__PGP__===========================")
    print("=========================================================")
    name = input("Enter your name\n>: ")
    email = input("Enter your email\n>: ")
    user = User(name, email)

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
            user.export_key_to_file(user.local_keychain, f'./private/{user.name}/keys/')
        if state == 4:
            user.import_key_from_file(f'./private/{user.name}/keys/file.pem')
        if state == 5:
            user.show_key_chain(password_in=input("[ENTER PASSWORD] >:"))
        if state == 6:
            mailboxAgent.send_message(user)


if __name__ == '__main__':
    main()