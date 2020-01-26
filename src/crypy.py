#!/usr/bin/env python

#########################
# CryPy - Sam Belliveau #
#########################
# CryPy is a command line tool that uses secure algorithms 
# to encrypt and decrypt files. 

from hashlib import scrypt
from os import urandom


def get_nonce(length):
    return urandom(int(length))

def get_hash(password, salt=b'', bytes=64):
    return scrypt(bytes(password), salt=bytes(salt), dklen=bytes)


class HashConfig:
    def __init__(this, length, id):
        this._length = length
        this._salt = get_hash(id)

    def hash(this, password, nonce, length=0):
        salt = (nonce + this._salt)
        if(length <= 0):
            return get_hash(password, salt, this._length)
        else:
            return get_hash(password, salt, length)



PasswordCheckHash = HashConfig(
    64, "Password Check Hash"
)

KeyGenerationHash = HashConfig(
    64, "Key Generation Hash"
)