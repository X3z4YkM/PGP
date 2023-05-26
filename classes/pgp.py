from datetime import date

from classes import user
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
                      session_algorythm, use_signature, use_zip, use_radix64):
    my_message = MessageDict.copy()
    my_message["filename"] = filename
    my_message["data"] = message
    my_message["timestamp"] = message_time

    my_pgp = PGPMessageDict.copy()
    my_pgp["radix64"] = use_radix64
    my_pgp["zip"] = use_zip
    my_pgp["secrecy"] = session_algorythm
    my_pgp["authentication"] = sign_encrypt_choice

    session_key = generate_session_key(session_algorythm)

    my_session_key = SessionKeyDict.copy()
    my_signature = SignatureDict.copy()

    if use_signature:
        # id for key pair of sender
        my_signature["sender_key_id"] = signing_key.public_key().export_key(format='DER')[-8:].hex()
        signature_timestamp = time.time()
        my_signature["timestamp"] = my_message["signature_timestamp"] = signature_timestamp
        message_hash = SHA1.new(pickle.dumps(my_message)).digest()
        my_signature["leading_octets"] = message_hash[2:]

        if sign_encrypt_choice == constants.SIGN_ENC_RSA:
            signature = signature_rsa(message_hash, signing_key)
        elif sign_encrypt_choice == constants.SIGN_ENC_DSA_ELGAMAL:
            signature = signature_dsa(message_hash, signing_key)
        my_signature["signature"] = signature

    if session_algorythm != constants.ALGORYTHM_NONE:
        if sign_encrypt_choice == constants.SIGN_ENC_RSA:
            session_key_encrypted = encrypt_rsa(encryption_key, session_key)
        elif sign_encrypt_choice == constants.SIGN_ENC_DSA_ELGAMAL:
            session_key_encrypted = encrypt_elgamal(encryption_key, session_key)
        else:
            raise ValueError("Invalid signature+encryption choice.")
        # id for key pair for recipient
        my_session_key["recipient_key_id"] = encryption_key.export_key(format='DER')[-8:].hex()
        my_session_key["session_key_cypher"] = session_key_encrypted

    # combine message and signature
    my_message_signature = MessageSignatureDict.copy()
    my_message_signature["message"] = my_message
    my_message_signature["signature"] = my_signature
    processed_message_signature = pickle.dumps(my_message_signature)
    # zip message
    if use_zip:
        processed_message_signature = zip_payload(processed_message_signature)

    # encrypt message+signature
    if session_algorythm == constants.ALGORYTHM_AES:
        processed_message_signature = encrypt_aes(session_key, processed_message_signature)
    elif session_algorythm == constants.ALGORYTHM_DES3:
        processed_message_signature = encrypt_des3(session_key, processed_message_signature)

    my_payload = PayloadDict.copy()
    my_payload["session_key_component"] = my_session_key
    my_payload["data"] = processed_message_signature
    my_pgp["payload"] = my_payload
    return base64.b64encode(pickle.dumps(my_pgp)) if use_radix64 else pickle.dumps(my_pgp)


def extract_and_validate_message(received_data, public_keyring, private_keyring):
    my_received = ReceivedDict.copy()

    return my_received


def signature_rsa(message_hash, signing_key: RSA.RsaKey):
    cipher = PKCS1_OAEP.new(signing_key)
    signed_hash = cipher.encrypt(message_hash)
    print("Signed Hash RSA:", signed_hash.hex())
    return signed_hash


def signature_dsa(message_hash, signing_key: DSA.DsaKey):
    signer = DSS.new(signing_key, 'fips-186-3')
    signed_hash = signer.sign(message_hash)
    print("Signed Hash DSA:", signed_hash.hex())
    return signed_hash


def encrypt_rsa(encryption_key: RSA.RsaKey, session_key):
    cipher_rsa = PKCS1_OAEP.new(encryption_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    print("Encrypted Session Key:", encrypted_session_key.hex())
    return encrypted_session_key


def encrypt_elgamal(encryption_key: ElGamal.ElGamalKey, session_key):
    encrypted_session_key = encryption_key.encrypt(session_key, None)
    print("Encrypted Key:", encrypted_session_key.hex())
    return encrypted_session_key


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


def generate_session_key(session_algorythm):
    if session_algorythm == constants.ALGORYTHM_AES:
        return get_random_bytes(16)
    elif session_algorythm == constants.ALGORYTHM_DES3:
        return get_random_bytes(24)
    else:
        None
