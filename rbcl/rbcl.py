"""
Python library that provides a simple interface for symmetric (*i.e.*,
secret-key) and asymmetric (*i.e.*, public-key) encryption/decryption
primitives.

This library exports a number of classes (derived from ``bytes``) for
representing keys, nonces, plaintexts, and ciphertexts. It also exports
two classes :obj:`symmetric` and :obj:`asymmetric` that have only static
methods (for key generation and encryption/decryption).
"""
from __future__ import annotations
from typing import Optional, Union
import doctest
import os
import base64

try:
    from rbcl import _sodium
except: # pylint: disable=W0702 # pragma: no cover
    # Support for direct invocation in order to execute doctests.
    import _sodium

crypto_scalarmult_ristretto255_BYTES = _sodium.lib.crypto_scalarmult_ristretto255_bytes()
crypto_scalarmult_ristretto255_SCALARBYTES = _sodium.lib.crypto_scalarmult_ristretto255_scalarbytes()
crypto_core_ristretto255_BYTES = _sodium.lib.crypto_core_ristretto255_bytes()
crypto_core_ristretto255_HASHBYTES = _sodium.lib.crypto_core_ristretto255_hashbytes()
crypto_core_ristretto255_NONREDUCEDSCALARBYTES = _sodium.lib.crypto_core_ristretto255_nonreducedscalarbytes()
crypto_core_ristretto255_SCALARBYTES = _sodium.lib.crypto_core_ristretto255_scalarbytes()
randombytes_SEEDBYTES = _sodium.lib.randombytes_seedbytes()

def crypto_core_ristretto255_is_valid_point(p):  # (const unsigned char *p);
    """
    Check if ``p`` represents a point on the ristretto255 curve, in canonical
    form, on the main subgroup, and that the point doesn't have a small order.

    :param p: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type p: bytes
    :return: point validity
    :rtype: bool
    """
    ensure(
        isinstance(p, bytes) and len(p) == crypto_core_ristretto255_BYTES,
        "Point must be a " + str(crypto_core_ristretto255_BYTES) + "long bytes sequence",
        raising=TypeError,
    )

    rc = lib.crypto_core_ristretto255_is_valid_point(p)
    return rc == 1

def crypto_core_ristretto255_add(p, q):  # (unsigned char *r, const unsigned char *p, const unsigned char *q);
    """
    Add two points on the ristretto255 curve.

    :param p: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type q: bytes
    :return: a point on the ristretto255 curve represented as
             a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(p, bytes)
        and isinstance(q, bytes)
        and len(p) == crypto_core_ristretto255_BYTES
        and len(q) == crypto_core_ristretto255_BYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_BYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)

    lib.crypto_core_ristretto255_add(r, p, q)

    return ffi.buffer(r, crypto_core_ristretto255_BYTES)[:]

def crypto_core_ristretto255_sub(p, q):  # (unsigned char *r, const unsigned char *p, const unsigned char *q);
    """
    Subtract a point from another on the ristretto255 curve.

    :param p: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type q: bytes
    :return: a point on the ristretto255 curve represented as
             a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(p, bytes)
        and isinstance(q, bytes)
        and len(p) == crypto_core_ristretto255_BYTES
        and len(q) == crypto_core_ristretto255_BYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_BYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)

    lib.crypto_core_ristretto255_sub(r, p, q)

    return ffi.buffer(r, crypto_core_ristretto255_BYTES)[:]

def crypto_core_ristretto255_from_hash(h):  # (unsigned char *p, const unsigned char *r);
    """
    Map a 64-byte vector ``h`` (usually the output of a hash function) to a ristretto255
    group element (a point), and output its representation in bytes.

    :param h: a :py:data:`.crypto_core_ristretto255_HASHBYTES`
              long bytes sequence ideally representing a hash digest
    :type h: bytes

    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(h, bytes)
        and len(h) == crypto_core_ristretto255_HASHBYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_HASHBYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)

    lib.crypto_core_ristretto255_from_hash(r, h)

    return ffi.buffer(r, crypto_core_ristretto255_BYTES)[:]

def crypto_core_ristretto255_random():  # (unsigned char *p);
    """
    Returns a ristretto255 group element (point).

    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALARBYTES)

    lib.crypto_core_ristretto255_random(r)

    return ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]

def crypto_core_ristretto255_scalar_random():  # (unsigned char *r);
    """
    Returns a :py:data:`.crypto_core_ristretto255_SCALARBYTES` byte long
    representation of the scalar in the ``[0..L]`` interval, ``L`` being the
    order of the group ``(2^252 + 27742317777372353535851937790883648493)``.

    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALARBYTES)

    lib.crypto_core_ristretto255_scalar_random(r)

    return ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]

def crypto_core_ristretto255_scalar_invert(p):  # (unsigned char *recip, const unsigned char *s);
    """
    Return the multiplicative inverse of integer ``s`` modulo ``L``,
    i.e an integer ``i`` such that ``s * i = 1 (mod L)``, where ``L``
    is the order of the main subgroup.

    Raises a ``RuntimeError`` if ``s`` is the integer zero.

    :param s: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type s: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(p, bytes)
        and len(p) == crypto_core_ristretto255_SCALARBYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_SCALARBYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALARBYTES)

    lib.crypto_core_ristretto255_scalar_invert(r, p)

    return ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]

def crypto_core_ristretto255_scalar_negate(p):  # (unsigned char *neg, const unsigned char *s);
    """
    Return the integer ``n`` such that ``s + n = 0 (mod L)``, where ``L``
    is the order of the main subgroup.

    :param s: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type s: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(p, bytes)
        and len(p) == crypto_core_ristretto255_SCALARBYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_SCALARBYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALARBYTES)

    lib.crypto_core_ristretto255_scalar_negate(r, p)

    return ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]

def crypto_core_ristretto255_scalar_complement(p):  # (unsigned char *comp, const unsigned char *s);
    """
    Return the complement of integer ``s`` modulo ``L``, i.e. an integer
    ``c`` such that ``s + c = 1 (mod L)``, where ``L`` is the order of
    the main subgroup.

    :param s: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type s: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(p, bytes)
        and len(p) == crypto_core_ristretto255_SCALARBYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_SCALARBYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALARBYTES)

    lib.crypto_core_ristretto255_scalar_complement(r, p)

    return ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]

def crypto_core_ristretto255_scalar_add(p, q):  # (unsigned char *z, const unsigned char *x, const unsigned char *y);
    
    """
    Add integers ``p`` and ``q`` modulo ``L``, where ``L`` is the order of
    the main subgroup.

    :param p: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type q: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(p, bytes)
        and isinstance(q, bytes)
        and len(p) == crypto_core_ristretto255_SCALARBYTES
        and len(q) == crypto_core_ristretto255_SCALARBYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_SCALARBYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALARBYTES)

    lib.crypto_core_ristretto255_scalar_add(r, p, q)

    return ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]

def crypto_core_ristretto255_scalar_sub(p, q):  # (unsigned char *z, const unsigned char *x, const unsigned char *y);
    """
    Subtract integers ``p`` and ``q`` modulo ``L``, where ``L`` is the
    order of the main subgroup.

    :param p: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type q: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(p, bytes)
        and isinstance(q, bytes)
        and len(p) == crypto_core_ristretto255_SCALARBYTES
        and len(q) == crypto_core_ristretto255_SCALARBYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_SCALARBYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALARBYTES)

    lib.crypto_core_ristretto255_scalar_sub(r, p, q)

    return ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]

def crypto_core_ristretto255_scalar_mul(p, q):  # (unsigned char *z, const unsigned char *x, const unsigned char *y);
    
    """
    Multiply integers ``p`` and ``q`` modulo ``L``, where ``L`` is the
    order of the main subgroup.

    :param p: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type q: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(p, bytes)
        and isinstance(q, bytes)
        and len(p) == crypto_core_ristretto255_SCALARBYTES
        and len(q) == crypto_core_ristretto255_SCALARBYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_SCALARBYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALARBYTES)

    lib.crypto_core_ristretto255_scalar_mul(r, p, q)

    return ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]

def crypto_core_ristretto255_scalar_reduce(p):  # (unsigned char *r, const unsigned char *s);
    """
    Reduce integer ``s`` to ``s`` modulo ``L``, where ``L`` is the order
    of the main subgroup.

    :param s: a :py:data:`.crypto_core_ristretto255_NONREDUCEDSCALARBYTES`
              long bytes sequence representing an integer
    :type s: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(p, bytes)
        and len(p) == crypto_core_ristretto255_SCALARBYTES,
        "Each integer must be a {} long bytes sequence".format(
            crypto_core_ristretto255_SCALARBYTES
        ),
        raising=TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALARBYTES)

    lib.crypto_core_ristretto255_scalar_reduce(r, p)

    return ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]

def crypto_scalarmult_ristretto255_base(n):
    """
    Computes and returns the scalar product of a standard group element and an
    integer ``n`` on the ristretto255 curve.

    :param n: a :py:data:`.crypto_scalarmult_ristretto255_SCALARBYTES` long bytes
              sequence representing a scalar
    :type n: bytes
    :return: a point on the ristretto255 curve, represented as a
             :py:data:`.crypto_scalarmult_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(n, bytes)
        and len(n) == crypto_scalarmult_ristretto255_SCALARBYTES,
        "Input must be a {} long bytes sequence".format(
            crypto_scalarmult_ristretto255_SCALARBYTES
        ),
        raising=TypeError,
    )

    q = ffi.new("unsigned char[]", crypto_scalarmult_ristretto255_BYTES)

    rc = lib.crypto_scalarmult_ristretto255_base(q, n)
    ensure(rc == 0, "Unexpected library error", raising=RuntimeError)

    return ffi.buffer(q, crypto_scalarmult_ristretto255_BYTES)[:]

def crypto_scalarmult_ristretto255(n, p):
    """
    Computes and returns the scalar product of a *clamped* integer ``n``
    and the given group element on the ristretto255 curve.
    The scalar is clamped, as done in the public key generation case,
    by setting to zero the bits in position [0, 1, 2, 255] and setting
    to one the bit in position 254.

    :param n: a :py:data:`.crypto_scalarmult_ristretto255_SCALARBYTES` long bytes
              sequence representing a scalar
    :type n: bytes
    :param p: a :py:data:`.crypto_scalarmult_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type p: bytes
    :return: a point on the ristretto255 curve, represented as a
             :py:data:`.crypto_scalarmult_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(
        isinstance(n, bytes)
        and len(n) == crypto_scalarmult_ristretto255_SCALARBYTES,
        "Input must be a {} long bytes sequence".format(
            crypto_scalarmult_ristretto255_SCALARBYTES
        ),
        raising=TypeError,
    )

    ensure(
        isinstance(p, bytes) and len(p) == crypto_scalarmult_ristretto255_BYTES,
        "Input must be a {} long bytes sequence".format(
            crypto_scalarmult_ristretto255_BYTES
        ),
        raising=TypeError,
    )

    q = ffi.new("unsigned char[]", crypto_scalarmult_ristretto255_BYTES)

    rc = lib.crypto_scalarmult_ristretto255(q, n, p)
    ensure(rc == 0, "Unexpected library error", raising=RuntimeError)

    return ffi.buffer(q, crypto_scalarmult_ristretto255_BYTES)[:]

def randombytes(size):
    """
    Returns ``size`` number of random bytes from a cryptographically secure
    random source.

    :param size: int
    :rtype: bytes
    """
    buf = ffi.new("unsigned char[]", size)
    lib.randombytes(buf, size)
    return ffi.buffer(buf, size)[:]

def randombytes_buf_deterministic(size, seed):
    """
    Returns ``size`` number of deterministically generated pseudorandom bytes
    from a seed

    :param size: int
    :param seed: bytes
    :rtype: bytes
    """
    if len(seed) != randombytes_SEEDBYTES:
        raise TypeError(
            "Deterministic random bytes must be generated from 32 bytes"
        )

    buf = ffi.new("unsigned char[]", size)
    lib.randombytes_buf_deterministic(buf, size, seed)
    return ffi.buffer(buf, size)[:]

# Initializes sodium, picking the best implementations available for this
# machine.
def _sodium_init():
    if _sodium.lib.sodium_init() == -1:
        raise RuntimeError("libsodium error during initialization") # pragma: no cover

_sodium.ffi.init_once(_sodium_init, "libsodium")

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
