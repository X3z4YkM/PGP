from classes import user
from modules import modules
from modules import constants
import time
import zlib
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.PublicKey import ElGamal


MessageDict = {
    "filename": None,
    "timestamp": None,
    "data": None
}

SignatureDict = {
    "timestamp": None,
    "sender_key_id": None,
    "leading_octets": None,
    "digest": None,  # encrypted for RSA, not encrypted for DSA
    "signature": None  # for DSA
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
    "session_key": SessionKeyDict.copy(),
    "encrypted_data": None
}

PGPMessageDict = {
    "radix64": None,
    "zip": None,
    "payload": None
}


def construct_message(filename, message, message_time, sign_encrypt_choice, signing_key, encryption_key, session_algorythm,
                      session_key, use_zip, use_radix64):

    my_message = MessageDict.copy()
    my_message["filename"] = filename
    my_message["data"] = message
    my_message["timestamp"] = message_time

    my_pgp = PGPMessageDict.copy()
    my_pgp["radix64"] = use_radix64
    my_pgp["zip"] = use_zip

    my_signature = SignatureDict.copy()
    #id for key pair of sender
    my_signature["sender_key_id"] = signing_key.public_key().export_key()[-8:].hex()
    my_signature["leading_octets"]

    message_hash = SHA1.new(message).digest()
    if sign_encrypt_choice == constants.SIGN_ENC_RSA:
        signature = signature_rsa(message_hash, signing_key)
        session_key_component = encrypt_rsa(encryption_key, session_key)
    elif sign_encrypt_choice == constants.SIGN_ENC_DSA_ELGAMAL:
        my_signature["digest"] = message_hash
        signature = signature_dsa(message_hash, signing_key)
        session_key_component = encrypt_elgamal(encryption_key, session_key)
    else:
        raise ValueError("Invalid signature+encryption choice.")

    my_signature["signature"] = signature
    my_signature["timestamp"] = time.time()

    my_message_signature = MessageSignatureDict.copy()
    my_message_signature["message"] = my_message
    my_message_signature["signature"] = signature

    my_session_key = SessionKeyDict.copy()
    #id for key pair for recipient
    my_session_key["recipient_key_id"] = encryption_key.export()[-8:].hex()
    my_session_key["session_key_cypher"] = session_key_component

    my_payload = PayloadDict.copy()
    my_payload["session_key"] = my_session_key
    if use_zip:
        payload = my_message_signature
    else:
        my_payload = my_message_signature
    my_payload["encrypted_data"] =


def signature_rsa(message_hash, signing_key):
    cipher = PKCS1_OAEP.new(signing_key)
    signed_hash = cipher.encrypt(message_hash)
    print("Signed Hash RSA:", signed_hash.hex())
    return signed_hash


def signature_dsa(message_hash, signing_key):
    signer = DSS.new(signing_key, 'fips-186-3')
    signed_hash = signer.sign(message_hash)
    print("Signed Hash DSA:", signed_hash.hex())
    return signed_hash


def encrypt_rsa(encryption_key, session_key):
    cipher_rsa = PKCS1_OAEP.new(encryption_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    print("Encrypted Session Key:", encrypted_session_key.hex())
    return encrypted_session_key


def encrypt_elgamal(encryption_key, session_key):
    encrypted_session_key = encryption_key.encrypt(session_key, None)
    print("Encrypted Key:", encrypted_session_key.hex())
    return encrypted_session_key

def zip_payload(payload):
    return zlib.compress(payload.encode())
def unzip_payload(payload):
    return zlib.decompress(payload.dencode())