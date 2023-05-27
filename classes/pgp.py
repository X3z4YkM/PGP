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
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

MessageDict = {
    "filename": None,
    "timestamp": None,
    "signature_timestamp": None,
    "data": None
}

SignatureDict = {
    "timestamp": None,
    "sender_key_id": None,
    "leading_octets": None,
    "signature": None
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
    "message": None,
    "signature": None,
    "signature_valid": None
}


def construct_message(filename, message, message_time, sign_encrypt_choice, signing_key, encryption_key,
                      session_algorithm, use_signature, use_zip, use_radix64):
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

    if use_signature:
        # id for key pair of sender
        my_signature["sender_key_id"] = signing_key.public_key().export_key(format='DER')[-8:].hex()
        signature_timestamp = time.time()
        my_signature["timestamp"] = my_message["signature_timestamp"] = signature_timestamp
        message_hash = SHA1.new(pickle.dumps(my_message)).digest()
        print("message hash:")
        print(message_hash)
        print("leading octets", message_hash[2:])
        my_signature["leading_octets"] = message_hash[2:]

        if sign_encrypt_choice == constants.SIGN_ENC_RSA:
            signature = signature_rsa(message_hash, signing_key)
        elif sign_encrypt_choice == constants.SIGN_ENC_DSA_ELGAMAL:
            signature = signature_dsa(message_hash, signing_key)
        my_signature["signature"] = signature

    if session_algorithm != constants.ALGORITHM_NONE:
        print("Generated session key", session_key)
        if sign_encrypt_choice == constants.SIGN_ENC_RSA:
            session_key_encrypted = encrypt_rsa(encryption_key, session_key)
        elif sign_encrypt_choice == constants.SIGN_ENC_DSA_ELGAMAL:
            session_key_encrypted = encrypt_elgamal(encryption_key, session_key)
        else:
            raise ValueError("Invalid signature+encryption choice.")
        # id for key pair for recipient
        my_session_key_component["recipient_key_id"] = encryption_key.export_key(format='DER')[-8:].hex()
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
    decrypted_message_signature = my_pgp["payload"]["data"]

    if my_pgp["zip"]:
        unzipped_message_signature = unzip_payload(decrypted_message_signature)
    else:
        unzipped_message_signature = decrypted_message_signature

    deserialized_message_signature = pickle.loads(unzipped_message_signature)

    if my_pgp["secrecy"] != constants.ALGORITHM_NONE:
        decryption_key = user.search_private_key(my_pgp["payload"]["session_key_component"]["recipient_key_id"])
        if my_pgp["authentication"] == constants.SIGN_ENC_RSA:
            session_key = decrypt_rsa(decryption_key, my_pgp["payload"]["session_key_component"]["session_key_cypher"])
        elif my_pgp["authentication"] == constants.SIGN_ENC_DSA_ELGAMAL:
            elgamal_key =  ElGamal.construct(DSA.import_key(decryption_key).domain())
            session_key = decrypt_elgamal(elgamal_key, my_pgp["payload"]["session_key_component"]["session_key_cypher"])
        else:
            raise ValueError("Unknown signing/key encryption algorithm.")

        if my_pgp["secrecy"] == constants.ALGORITHM_AES:
            decrypted_message_signature = decrypt_aes(session_key, deserialized_message_signature)
        elif my_pgp["secrecy"] == constants.ALGORITHM_DES3:
            decrypted_message_signature = decrypt_des3(session_key, deserialized_message_signature)
        else:
            raise ValueError("Unknown encryption algorithm", my_pgp["secrecy"])
    else:
        decrypted_message_signature = deserialized_message_signature

    my_message = decrypted_message_signature["message"]
    my_received["message"] = str(my_message["filename"]) + "\n" + datetime.datetime.fromtimestamp(
        my_message["timestamp"]).strftime('%H:%M:%S %d-%m-%Y') + "\n" + str(my_message["data"])
    my_signature = decrypted_message_signature["signature"]
    # check signature
    if my_pgp["signed"]:
        my_received["signature"] = my_signature["signature"]
        message_hash = SHA1.new(pickle.dumps(my_message)).digest()
        if my_signature["leading_octets"] != message_hash[2:]:
            my_received["signature_valid"] = False
        if my_signature["timestamp"] != my_message["signature_timestamp"]:
            my_received["signature_valid"] = False

        signature_decryption_key = user.search_public_key(my_signature["sender_key_id"])
        if my_pgp["authentication"] == constants.SIGN_ENC_RSA:
            my_received["signature_valid"] = verify_signature_rsa(message_hash, my_signature["signature"],
                                                                  signature_decryption_key)
        elif my_pgp["authentication"] == constants.SIGN_ENC_DSA_ELGAMAL:
            my_received["signature_valid"] = verify_signature_dsa(message_hash, my_signature["signature"],
                                                                  signature_decryption_key)
    pp.pprint(my_received)
    return my_received


def signature_rsa(message_hash, signing_key: RSA.RsaKey):
    signed_hash = encrypt_rsa(signing_key, message_hash)
    print("Signed Hash RSA:", signed_hash.hex())
    return signed_hash


def verify_signature_rsa(message_hash, signature, signature_check_key: RSA.RsaKey):
    signer = RSA.new(signature_check_key, 'fips-186-3')
    return signer.verify(message_hash, signature)


def signature_dsa(message_hash, signing_key: DSA.DsaKey):
    signer = DSS.new(signing_key, 'fips-186-3')
    signed_hash = signer.sign(message_hash)
    print("Signed Hash DSA:", signed_hash.hex())
    return signed_hash


def verify_signature_dsa(message_hash, signature, signature_check_key: DSA.DsaKey):
    signer = DSS.new(signature_check_key, 'fips-186-3')
    return signer.verify(message_hash, signature)


def encrypt_rsa(encryption_key: RSA.RsaKey, data):
    cipher_rsa = PKCS1_OAEP.new(encryption_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data


def decrypt_rsa(decryption_key: RSA.RsaKey, encrypted_data):
    cipher_rsa = PKCS1_OAEP.new(decryption_key)
    data = cipher_rsa.decrypt(encrypted_data)
    return data


def encrypt_elgamal(encryption_key: ElGamal.ElGamalKey, data):
    cipher = PKCS1_OAEP.new(encryption_key)
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


def decode_if_base64(data):
    try:
        return base64.b64decode(data)
    except (base64.binascii.Error, UnicodeDecodeError):
        return data
