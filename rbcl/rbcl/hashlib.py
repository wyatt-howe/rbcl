# Copyright 2016-2019 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import binascii

import rbcl.bindings
from rbcl.utils import bytes_as_string

BYTES = rbcl.bindings.crypto_generichash_BYTES
BYTES_MIN = rbcl.bindings.crypto_generichash_BYTES_MIN
BYTES_MAX = rbcl.bindings.crypto_generichash_BYTES_MAX
KEYBYTES = rbcl.bindings.crypto_generichash_KEYBYTES
KEYBYTES_MIN = rbcl.bindings.crypto_generichash_KEYBYTES_MIN
KEYBYTES_MAX = rbcl.bindings.crypto_generichash_KEYBYTES_MAX
SALTBYTES = rbcl.bindings.crypto_generichash_SALTBYTES
PERSONALBYTES = rbcl.bindings.crypto_generichash_PERSONALBYTES

SCRYPT_AVAILABLE = rbcl.bindings.has_crypto_pwhash_scryptsalsa208sha256

_b2b_init = rbcl.bindings.crypto_generichash_blake2b_init
_b2b_final = rbcl.bindings.crypto_generichash_blake2b_final
_b2b_update = rbcl.bindings.crypto_generichash_blake2b_update


class blake2b(object):
    """
    :py:mod:`hashlib` API compatible blake2b algorithm implementation
    """

    MAX_DIGEST_SIZE = BYTES
    MAX_KEY_SIZE = KEYBYTES_MAX
    PERSON_SIZE = PERSONALBYTES
    SALT_SIZE = SALTBYTES

    def __init__(
        self, data=b"", digest_size=BYTES, key=b"", salt=b"", person=b""
    ):
        """
        :py:class:`.blake2b` algorithm initializer

        :param data:
        :type data: bytes
        :param int digest_size: the requested digest size; must be
                                at most :py:attr:`.MAX_DIGEST_SIZE`;
                                the default digest size is :py:data:`.BYTES`
        :param key: the key to be set for keyed MAC/PRF usage; if set,
                    the key must be at most :py:data:`.KEYBYTES_MAX` long
        :type key: bytes
        :param salt: a initialization salt at most
                     :py:attr:`.SALT_SIZE` long; it will be zero-padded
                     if needed
        :type salt: bytes
        :param person: a personalization string at most
                       :py:attr:`.PERSONAL_SIZE` long; it will be zero-padded
                       if needed
        :type person: bytes
        """

        self._state = _b2b_init(
            key=key, salt=salt, person=person, digest_size=digest_size
        )
        self._digest_size = digest_size

        if data:
            self.update(data)

    @property
    def digest_size(self):
        return self._digest_size

    @property
    def block_size(self):
        return 128

    @property
    def name(self):
        return "blake2b"

    def update(self, data):
        _b2b_update(self._state, data)

    def digest(self):
        _st = self._state.copy()
        return _b2b_final(_st)

    def hexdigest(self):
        return bytes_as_string(binascii.hexlify(self.digest()))

    def copy(self):
        _cp = type(self)(digest_size=self.digest_size)
        _st = self._state.copy()
        _cp._state = _st
        return _cp

    def __reduce__(self):
        """
        Raise the same exception as hashlib's blake implementation
        on copy.copy()
        """
        raise TypeError(
            "can't pickle {} objects".format(self.__class__.__name__)
        )


def scrypt(password, salt="", n=2 ** 20, r=8, p=1, maxmem=2 ** 25, dklen=64):
    """
    Derive a cryptographic key using the scrypt KDF.

    :raises rbcl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.

    Implements the same signature as the ``hashlib.scrypt`` implemented
    in cpython version 3.6
    """
    return rbcl.bindings.crypto_pwhash_scryptsalsa208sha256_ll(
        password, salt, n, r, p, maxmem=maxmem, dklen=dklen
    )
