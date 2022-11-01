import base64
import os
import secrets
from random import Random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.fernet import Fernet

class Protocol:
    delimiter = b"|"
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.nonce_A = None
        self.nonce_B = None
        pass

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, isServer):
        nonce = secrets.token_urlsafe(12)
        self.nonce_A = nonce.encode()
        # print("nonce_A is:" + nonce)
        if isServer:
            return "PROTOCOL SERVER" + nonce
        return "PROTOCOL CLIENT" + nonce

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return message.startswith(b"PROTOCOL")

    def generate_message_to_encrypt(self, isServer, response, session_key):
        padder = padding.PKCS7(128).padder()
        if isServer:
            data = b"SERVER" + self.delimiter + response + self.delimiter + session_key
        else:
            data = b"CLIENT" + self.delimiter + response + self.delimiter + session_key
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message, shared_key):
        unpadder = padding.PKCS7(128).unpadder()
        ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=None)
        key = ckdf.derive(shared_key.encode())
        cipher = Cipher(algorithms.AES(key), modes.ECB())

        if message.startswith(b"PROTOCOL CLIENT"):
            nonce_B = secrets.token_urlsafe(12)
            self.nonce_B = nonce_B.encode() #Rb

            message_string = message.decode()
            header_length = len("PROTOCOL CLIENT")
            nonce_A = message_string[header_length:].encode()

            session_key = secrets.token_urlsafe(32).encode()
            self.SetSessionKey(session_key)

            data = self.generate_message_to_encrypt(True, session_key, nonce_A)

            encryptor = cipher.encryptor()
            encrypted_nonce_session_key = encryptor.update(data) + encryptor.finalize()
            handshake_message = b"PROTOCOL SERVER RESPONSE" + self.nonce_B + encrypted_nonce_session_key
            return handshake_message
        elif message.startswith(b"PROTOCOL SERVER"):
            nonce_B = secrets.token_urlsafe(12)
            self.nonce_B = nonce_B.encode()  # Rb

            message_string = message.decode()
            header_length = len("PROTOCOL SERVER")
            nonce_A = message_string[header_length:].encode()

            session_key = secrets.token_urlsafe(32).encode()
            self.SetSessionKey(session_key)

            data = self.generate_message_to_encrypt(False, session_key, nonce_A)

            encryptor = cipher.encryptor()
            encrypted_nonce_session_key = encryptor.update(data) + encryptor.finalize()
            handshake_message = b"PROTOCOL CLIENT RESPONSE" + self.nonce_B + encrypted_nonce_session_key
            return handshake_message
        elif message.startswith(b"PROTOCOL CLIENT RESPONSE"):
            header_length = len("PROTOCOL CLIENT RESPONSE")
            length_of_nonce_B = len(self.nonce_B.decode())

            message_string = message.decode()
            encMessage = message_string[(header_length+length_of_nonce_B):]

            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encMessage) + decryptor.finalize()

            try:
                data = unpadder.update(padded_data) + unpadder.finalize()
                data = data.split(self.delimiter, 2)
                if data[0] == b"CLIENT" and data[1] == self.nonce_A:
                    session_key = data[2]
                    self.SetSessionKey(session_key)
            except:
                raise Exception("Authentication fails")

            nonce_B = secrets.token_urlsafe(12)
            self.nonce_B = nonce_B.encode()  # Rb

            session_key = secrets.token_urlsafe(32)
            self.SetSessionKey(session_key)
            data = self.generate_message_to_encrypt(True, session_key, nonce_B)

            encryptor = cipher.encryptor()
            encrypted_nonce_session_key = encryptor.update(data) + encryptor.finalize()
            handshake_message = b"PROTOCOL SERVER RESPONSE 2" + self.nonce_B + encrypted_nonce_session_key
            return handshake_message
        elif message.startswith(b"PROTOCOL SERVER RESPONSE"):
            header_length = len("PROTOCOL SERVER RESPONSE")
            length_of_nonce_B = len(self.nonce_B.decode())

            message_string = message.decode()
            encMessage = message_string[(header_length + length_of_nonce_B):]

            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encMessage) + decryptor.finalize()

            try:
                data = unpadder.update(padded_data) + unpadder.finalize()
                data = data.split(self.delimiter, 2)
                if data[0] == b"SERVER" and data[1] == self.nonce_A:
                    session_key = data[2]
                    self.SetSessionKey(session_key)
            except:
                raise Exception("Authentication fails")

            nonce_B = secrets.token_urlsafe(12)
            self.nonce_B = nonce_B.encode()  # Rb

            session_key = secrets.token_urlsafe(32)
            self.SetSessionKey(session_key)
            data = self.generate_message_to_encrypt(False, session_key, nonce_B)

            encryptor = cipher.encryptor()
            encrypted_nonce_session_key = encryptor.update(data) + encryptor.finalize()
            handshake_message = b"PROTOCOL CLIENT RESPONSE 2" + self.nonce_B + encrypted_nonce_session_key
            return handshake_message
        elif message.startswith(b"PROTOCOL CLIENT RESPONSE 2"):
            header_length = len("PROTOCOL CLIENT RESPONSE 2")
            message_string = message.decode()

            encMessage = message_string[header_length:]

            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encMessage) + decryptor.finalize()

            try:
                data = unpadder.update(padded_data) + unpadder.finalize()
                data = data.split(self.delimiter, 2)
                if data[0] == b"CLIENT" and data[1] == self.nonce_B:
                    session_key = data[2]
                    assert (self._key == session_key)
            except:
                raise Exception("Authentication fails")

            handshake_message = b"PROTOCOL_END"
            return handshake_message
        elif message.startswith(b"PROTOCOL SERVER RESPONSE 2"):
            header_length = len("PROTOCOL SERVER RESPONSE 2")
            message_string = message.decode()

            encMessage = message_string[header_length:]

            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encMessage) + decryptor.finalize()

            try:
                data = unpadder.update(padded_data) + unpadder.finalize()
                data = data.split(self.delimiter, 2)
                if data[0] == b"SERVER" and data[1] == self.nonce_B:
                    session_key = data[2]
                    assert (self._key == session_key)
            except:
                raise Exception("Authentication fails")

            handshake_message = b"PROTOCOL_END"
            return handshake_message
        pass

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass

    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text

    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
