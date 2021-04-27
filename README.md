## RbCl

Ristretto group Python binding to [libsodium](https://github.com/jedisct1/libsodium)

RbCl supports Python 2.7 and 3.5+ as
well as PyPy 2.6+.

The following bindings are made available:

### [Constructors](https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#encoded-element-validation)
```
crypto_core_ristretto255_random
crypto_core_ristretto255_from_hash
crypto_core_ristretto255_is_valid_point
```

### [Scalar arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#scalar-arithmetic-over-l)
```
crypto_core_ristretto255_scalar_add
crypto_core_ristretto255_scalar_complement
crypto_core_ristretto255_scalar_invert
crypto_core_ristretto255_scalar_mul
crypto_core_ristretto255_scalar_negate
crypto_core_ristretto255_scalar_random
crypto_core_ristretto255_scalar_reduce
crypto_core_ristretto255_scalar_sub
```

### [Point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#scalar-multiplication)
```
crypto_core_ristretto255_add
crypto_core_ristretto255_sub
crypto_scalarmult_ristretto255
crypto_scalarmult_ristretto255_base
```

### Constants
```
crypto_scalarmult_ristretto255_bytes
crypto_scalarmult_ristretto255_scalarbytes
crypto_core_ristretto255_bytes
crypto_core_ristretto255_scalarbytes
crypto_core_ristretto255_hashbytes
crypto_core_ristretto255_nonreducedscalarbytes
```

### Helpers
```
sodium_bin2hex
sodium_hex2bin
sodium_base642bin
sodium_base64_encoded_len
sodium_bin2base64
sodium_pad
sodium_unpad
```
