import datetime
import pprint
from classes import user
from classes.user import User
from modules import modules
from modules import constants
import time
import zlib
import pickle
import base64
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES3, AES
from Crypto.PublicKey import DSA, ElGamal
from Crypto.Signature import DSS, PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

MessageDict = {
    "filename": None,
    "timestamp": None,
    "signature_timestamp": None,
    "data": None
}

SignatureDict = {
    "signature": None,
    "timestamp": None,
    "sender_key_id": None,
    "leading_octets": None
}

MessageSignatureDict = {
    "signature": SignatureDict.copy(),
    "message": MessageDict.copy()
}

SessionKeyDict = {
    "recipient_key_id": None,
    "session_key_cypher": None
}

PayloadDict = {
    "session_key_component": SessionKeyDict.copy(),
    "data": None
}

PGPMessageDict = {
    "radix64": None,
    "zip": None,
    "signed": None,
    "secrecy": None,
    "authentication": None,
    "payload": None
}

ReceivedDict = {
    "message": "",
    "signature": None,
    "signature_valid": False
}


def construct_message(filename, message, message_time, key_password, signing_key_record, encryption_key_record,
                      session_algorithm, use_signature, use_zip, use_radix64):
    signing_key_pem = User.decrypt_private_key(signing_key_record["private_key"], key_password)
    if user.check_rsa_key_header_private(signing_key_pem):
        sign_encrypt_choice = constants.SIGN_ENC_RSA
        signing_key = RSA.import_key(signing_key_pem)
        encryption_key = RSA.import_key(encryption_key_record["public_key"])
    elif user.check_dsa_key_header_private(signing_key_pem):
        sign_encrypt_choice = constants.SIGN_ENC_DSA_ELGAMAL
        signing_key = DSA.import_key(signing_key_pem)
        if session_algorithm != constants.ALGORITHM_NONE:
            encryption_key = ElGamal.construct(DSA.import_key(encryption_key_record["public_key"]).domain())
    else:
        raise ValueError("Selected keys not RSA or DSA!")

    signing_key_id = signing_key_record["key_id"]
    encryption_key_id = encryption_key_record["key_id"]

    my_message = MessageDict.copy()
    my_message["filename"] = filename
    my_message["data"] = message
    my_message["timestamp"] = message_time

    my_pgp = PGPMessageDict.copy()
    my_pgp["radix64"] = use_radix64
    my_pgp["zip"] = use_zip
    my_pgp["signed"] = use_signature
    my_pgp["secrecy"] = session_algorithm
    my_pgp["authentication"] = sign_encrypt_choice

    session_key = generate_session_key(session_algorithm)

    my_session_key_component = SessionKeyDict.copy()
    my_signature = SignatureDict.copy()

    # signature
    if use_signature:
        my_signature["sender_key_id"] = signing_key_id
        signature_timestamp = time.time()
        my_signature["timestamp"] = my_message["signature_timestamp"] = signature_timestamp
        message_hash = SHA1.new(pickle.dumps(my_message))
        message_digest = message_hash.digest()
        my_signature["leading_octets"] = message_digest[:2]

        if sign_encrypt_choice == constants.SIGN_ENC_RSA:
            signature = sign_rsa(message_hash, signing_key)
        elif sign_encrypt_choice == constants.SIGN_ENC_DSA_ELGAMAL:
            signature = signature_dsa(message_hash, signing_key)
        # signature = tamper_signature(signature)
        my_signature["signature"] = signature

    # encrypt session key
    if session_algorithm != constants.ALGORITHM_NONE:
        print("Generated session key", session_key)
        if sign_encrypt_choice == constants.SIGN_ENC_RSA:
            session_key_encrypted = encrypt_rsa(encryption_key, session_key)
        elif sign_encrypt_choice == constants.SIGN_ENC_DSA_ELGAMAL:
            session_key_encrypted = encrypt_elgamal(encryption_key, session_key)
        else:
            raise ValueError("Invalid signature+encryption choice.")
        # id for key pair for recipient
        my_session_key_component["recipient_key_id"] = encryption_key_id
        my_session_key_component["session_key_cypher"] = session_key_encrypted

    # combine message and signature
    my_message_signature = MessageSignatureDict.copy()
    my_message_signature["message"] = my_message
    my_message_signature["signature"] = my_signature
    processed_message_signature = pickle.dumps(my_message_signature)
    # zip message
    if use_zip:
        processed_message_signature = zip_payload(processed_message_signature)

    # encrypt message+signature
    if session_algorithm == constants.ALGORITHM_AES:
        processed_message_signature = encrypt_aes(session_key, processed_message_signature)
    elif session_algorithm == constants.ALGORITHM_DES3:
        processed_message_signature = encrypt_des3(session_key, processed_message_signature)

    my_payload = PayloadDict.copy()
    my_payload["session_key_component"] = my_session_key_component
    my_payload["data"] = processed_message_signature
    my_pgp["payload"] = my_payload
    return base64.b64encode(pickle.dumps(my_pgp)) if use_radix64 else pickle.dumps(my_pgp)


def extract_and_validate_message(received_data, user: User):
    pp = pprint.PrettyPrinter(depth=4)

    my_received = ReceivedDict.copy()
    my_pgp = pickle.loads(decode_if_base64(received_data))
    print("my_pgp")
    print(my_pgp["radix64"])
    print("zipped:", my_pgp["zip"])
    print("signed:", my_pgp["signed"])
    print(my_pgp["secrecy"])
    print(my_pgp["authentication"])
    pp.pprint(my_pgp["payload"])
    data_message_signature = my_pgp["payload"]["data"]

    if my_pgp["secrecy"] != constants.ALGORITHM_NONE:
        decryption_key = user.search_private_key(my_pgp["payload"]["session_key_component"]["recipient_key_id"])
        if my_pgp["authentication"] == constants.SIGN_ENC_RSA:
            session_key = decrypt_rsa(decryption_key, my_pgp["payload"]["session_key_component"]["session_key_cypher"])
        elif my_pgp["authentication"] == constants.SIGN_ENC_DSA_ELGAMAL:
            elgamal_key = ElGamal.construct(DSA.import_key(decryption_key).domain())
            session_key = decrypt_elgamal(elgamal_key, my_pgp["payload"]["session_key_component"]["session_key_cypher"])
        else:
            raise ValueError("Unknown signing/key encryption algorithm.")

        if my_pgp["secrecy"] == constants.ALGORITHM_AES:
            decrypted_message_signature = decrypt_aes(session_key, data_message_signature)
        elif my_pgp["secrecy"] == constants.ALGORITHM_DES3:
            decrypted_message_signature = decrypt_des3(session_key, data_message_signature)
        else:
            raise ValueError("Unknown encryption algorithm", my_pgp["secrecy"])
    else:
        decrypted_message_signature = data_message_signature

    if my_pgp["zip"]:
        unzipped_message_signature = unzip_payload(decrypted_message_signature)
    else:
        unzipped_message_signature = decrypted_message_signature

    deserialized_message_signature = pickle.loads(unzipped_message_signature)

    my_message = deserialized_message_signature["message"]
    my_received["message"] = str(my_message["filename"]) + "\n" + datetime.datetime.fromtimestamp(
        my_message["timestamp"]).strftime('%H:%M:%S %d-%m-%Y') + "\n" + str(my_message["data"])
    my_signature = decrypted_message_signature["signature"]
    # check signature
    if my_pgp["signed"]:
        my_received["signature"] = my_signature["signature"]
        message_hash = SHA1.new(pickle.dumps(my_message))
        message_digest = message_hash.digest()
        if my_signature["leading_octets"] != message_digest[:2]:
            my_received["signature_valid"] = False
        elif my_signature["timestamp"] != my_message["signature_timestamp"]:
            my_received["signature_valid"] = False
        elif my_pgp["authentication"] == constants.SIGN_ENC_RSA:
            signature_decryption_key = RSA.import_key(
                user.search_public_key(my_signature["sender_key_id"])["public_key"])
            my_received["signature_valid"] = verify_rsa(message_hash, my_signature["signature"],
                                                        signature_decryption_key)
        elif my_pgp["authentication"] == constants.SIGN_ENC_DSA_ELGAMAL:
            signature_decryption_key = DSA.import_key(
                user.search_public_key(my_signature["sender_key_id"])["public_key"])
            my_received["signature_valid"] = verify_dsa(message_hash, my_signature["signature"],
                                                        signature_decryption_key)
    return my_received


def sign_rsa(message_hash, signing_key: RSA.RsaKey):
    signer = PKCS1_v1_5.new(signing_key)
    return signer.sign(message_hash)


def verify_rsa(message_hash, signature, signature_check_key: RSA.RsaKey):
    signer = PKCS1_v1_5.new(signature_check_key)
    return signer.verify(message_hash, signature)


def signature_dsa(message_hash, signing_key: DSA.DsaKey):
    signer = DSS.new(signing_key, 'fips-186-3')
    signed_hash = signer.sign(message_hash)
    return signed_hash


def verify_dsa(message_hash, signature, signature_check_key: DSA.DsaKey):
    try:
        signer = DSS.new(signature_check_key, 'fips-186-3')
        signer.verify(message_hash, signature)
        return True
    except ValueError:
        print("GRESKA GRESKA GRESKA")
        return False


def encrypt_rsa(encryption_key: RSA.RsaKey, data):
    cipher = PKCS1_OAEP.new(encryption_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data


def decrypt_rsa(decryption_key: RSA.RsaKey, encrypted_data):
    cipher = PKCS1_OAEP.new(decryption_key)
    data = cipher.decrypt(encrypted_data)
    return data


def encrypt_elgamal(encryption_key: ElGamal.ElGamalKey, data):
    cipher = ElGamal.new(encryption_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data


def decrypt_elgamal(decryption_key: ElGamal.ElGamalKey, encrypted_data):
    cipher = PKCS1_OAEP.new(decryption_key)
    data = cipher.decrypt(encrypted_data)
    return data


def encrypt_des3(session_key, data):
    cipher = DES3.new(session_key, DES3.MODE_CBC)
    padded_data = pad(data, DES3.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return cipher.iv + encrypted_data


def decrypt_des3(session_key, encrypted_data):
    iv = encrypted_data[:DES3.block_size]
    cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data[DES3.block_size:])
    return unpad(decrypted_data, DES3.block_size)


def encrypt_aes(session_key, data):
    cipher = AES.new(session_key, AES.MODE_CBC)
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return cipher.iv + encrypted_data


def decrypt_aes(session_key, encrypted_data):
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
    return unpad(decrypted_data, AES.block_size)


def zip_payload(payload):
    return zlib.compress(payload)


def unzip_payload(payload):
    return zlib.decompress(payload)


def generate_session_key(session_algorithm):
    if session_algorithm == constants.ALGORITHM_AES:
        return get_random_bytes(16)
    elif session_algorithm == constants.ALGORITHM_DES3:
        return get_random_bytes(24)
    else:
        None


def tamper_signature(signature):
    byte_array = bytearray(signature)
    byte_array[3] = 0x8c
    return bytes(byte_array)


def decode_if_base64(data):
    try:
        return base64.b64decode(data)
    except (base64.binascii.Error, UnicodeDecodeError):
        return data