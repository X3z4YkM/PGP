from classes import user


class MailBox:
    def send_message(self, user_info):
        message_to_send = input("[MESSAGE] >: ")
        encryption_state = input("[OPTION] do you want to encrypt your message (y/n) >: ")
        encryption_method = None
        signature_key_index = None

        if encryption_state.lower() == 'y':
            encryption_method = input(f"[ENCRYPTION OPTIONS]\n{'-'*20}\n1)TripleDES\n2)AES128\n>:")
        signature_state = input("[OPTION] do you want to signe the message (y/n) >: ")
        if signature_state.lower() == 'y':
            user_info.show_keychain_private
            signature_key_index = input(">:")

        print({
            "encryption_method ":encryption_method,
            "signature_key_index ":signature_key_index,
            "message ": message_to_send})




