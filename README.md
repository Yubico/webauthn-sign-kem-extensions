# `arkg` WebAuthn extension

This extension enables Relying Parties to perform cryptographic operations using
the [Asynchronous Remote Key Generation (ARKG)][arkg] protocol, with the authenticator holding all secret key material.

The protocol begins with the authenticator emitting a _seed public key_.
The Relying Party can use the seed public key to generate any number of _derived public keys_,
but the Relying Party does not gain access to the corresponding private keys.
Derived public keys on their own are unlinkable; given two derived public keys
it is impossible to determine whether they were derived from the same seed
public key or were generated independently.

Finally, the Relying Party can request two operations from the authenticator:

- Given a derived public key _P_, derive the private key _p_ corresponding to
  _P_ and generate a signature using _p_.
  
  This enables the Relying Party to sign arbitrary data using public keys that
  can be generated in advance without access to the authenticator. For example,
  this could be used in scenarios where each signature uses a unique public key
  to prevent tracking, where many public keys could be generated in advance for
  later offline use.

- Given a derived public key _P_ and an ephemeral public key _E_, derive the
  private key _p_ corresponding to _P_ and perform a Diffie-Hellman exchange
  between _p_ and _E_.
  
  This gives the Relying Party access to a random oracle similar to the `prf`
  extension, but with the difference that a shared secret can be initially
  generated without access to the authenticator. For example, this could be used
  for asymmetric encryption where the authenticator needs to be present only
  during decryption.

The following terms are used throughout this document:

- `LEFT(X, n)` is the first `n` bytes of the byte array `X`.
- `DROP_LEFT(X, n)` is the byte array `X` without the first `n` bytes.
- CTAP2_ERR_X represents some not yet specified error code.


## Authenticator operations

### Generate ARKG seed

`createSeed` input:
```js
extensions: {
    arkg: {
        createSeed: {
            pubKeyCredParams: sequence<PublicKeyCredentialParameters>,
            salt: BufferSource,
            uv: bool,
            usage: sequence<"sign" | "ecdh">,
        },
    },
},
```

Authenticator processing steps:

 1. Let `alg` be the authenticator's choice of one of the algorithms listed in `pubKeyCredParams`.
    `alg` MUST be a fully-specified COSEAlgorithmIdentifier with a single valid corresponding curve `crv`.
    Let `crv` be this curve.
    
    ISSUE: Support non-EC algorithms too? ARKG can in principle work with any
    discrete logarithm problem, and post-quantum extensions also exist.

    ISSUE: There's probably some overlap and conflict between `alg` and `usage` here?
    For example, `alg: -7 (ES256)` and `usage: "ecdh"` doesn't make sense, since `ES256` is specifically a signing algorithm.
    Perhaps there should be a list of curves instead of `pubKeyCredParams`, and a list of `alg`s instead of `usage`?
    The COSE_Key format allows only one `alg` ("Key usage restriction to this algorithm") value per key,
    so should each seed public key only support deriving public keys of the same single `alg`?
    Or should the seed public key contain only a `crv` field but not an `alg` field?

 2. If `usage` is empty, return CTAP2_ERR_X.

 3. If `usage` includes `"sign"` and `crv` is not valid for signature operations, return CTAP2_ERR_X.
 
    Note: For example, COSE elliptic curve `4` (X25519) is valid for use with ECDH only.

 4. If `usage` includes `"ecdh"` and `crv` is not valid for Elliptic Curve
    Diffie-Hellman (ECDH) operations, return CTAP2_ERR_X.

    Note: For example, COSE elliptic curve `6` (Ed25519) is valid for use with EdDSA only.

 5. Use `salt`, `uv`, `usage` and a per-credential authenticator secret as the
    seed to deterministically generate a new EC key pair `s, S` on the curve
    `crv`.

 6. Let `S_enc` be `S` encoded in COSE_Key format.
 
 7. Let `seedHandle` be an authenticator-specific encoding of `crv`, `salt`,
    `uv` and `usage` which the authenticator can later use to derive the same EC
    key pair `s, S`. The encoding SHOULD include integrity protection to ensure
    that a given `seedHandle` is valid for a particular authenticator.
    
    One possible implementation is as follows:

     1. Let `seedMacKey` be a per-credential authenticator secret.

     2. Let `seedHandleParams = [alg, salt, uv, usage]` as CBOR.

     3. Let `seedHandle = HMAC-SHA-256(seedMacKey, seedHandleParams || rpIdHash) || seedHandleParams`.

 8. Return `seedPublicKey: S` and `seedHandle: seedHandle`.

`createSeed` output:
```js
authData.extensions: {
    arkg: {
        seedPublicKey: ArrayBuffer,  // ARKG public key seed in COSE_Key format
        seedHandle: ArrayBuffer,     // Private seed re-derivation parameters
    },
},
```


### Sign arbitrary data

`sign` input:
```js
extensions: {
    arkg: {
        sign: {
            tbs: BufferSource,                 // Data to sign
            keyHandle: {
                seedHandle:     BufferSource,  // seedHandle from createSeed output
                ecdhePublicKey: BufferSource,  // `E` field of `cred` parameter of DeriveSK in ARKG
                mac:            BufferSource,  // `µ` field of `cred` parameter of DeriveSK in ARKG
            },
        },
    },
},
```

Authenticator processing steps:

 1. Decode the authenticator-specific encoding of `seedHandle` to extract the
    `alg`, `salt`, `uv` and `usage` values. This procedure SHOULD verify
    integrity to ensure that `seedHandle` was generated by this authenticator.

    One possible implementation, compatible with the example encoding described above for `createSeed`, is as follows:

     1. Let `seedMacKey` be a per-credential authenticator secret.

     2. Let `mac = LEFT(32, seedHandle)` and `seedHandleParams = DROP_LEFT(32, seedHandle)`.

     3. Verify that `mac == HMAC-SHA-256(seedMacKey, seedHandleParams || rpIdHash)`. If
        not, this `seedHandle` was generated by a different authenticator. Return CTAP2_ERR_X.

     4. Parse `[alg, salt, uv, usage] = seedHandleParams` as CBOR.
     
     5. Return `(alg, salt, uv, usage`).

    `alg` MUST be a fully-specified COSEAlgorithmIdentifier with a single valid corresponding curve `crv`.
    Let `crv` be this curve.

 2. If `usage` does not include `"sign"`, return CTAP2_ERR_X.
    
 3. Use `salt`, `uv` and a per-credential authenticator secret as the seed to
    deterministically regenerate the EC key pair `s, S` on the curve `crv`.

 4. Let `E` be the public key on the curve `crv` decoded from the uncompressed
    point `keyHandle.ecdhePublicKey` as described in [SEC 1][sec1], section
    2.3.4. If invalid, return CTAP2_ERR_X.
    
    ISSUE: Should `E` use COSE_Key format instead of SEC1?

 5. If `E` is the point at infinity, return CTAP2_ERR_X.

 6. Let `ikm = ECDH(s, E)`. Let `ikm_x` be the X coordinate of `ikm`, encoded as
    a byte string of length 32 as described in [SEC 1][sec1], section 2.3.7.

 7. Let `credKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf]
    with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.arkg.sign.cred_key` encoded as a UTF-8 byte string.
    - `L`: 32.

    Parse `credKey` as a big-endian unsigned number in the scalar field of `crv`.
    If `credKey` is greater than the order of the curve `crv`, return CTAP2_ERR_X.

 8. Let `macKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf]
    with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.arkg.sign.mac_key` encoded as a UTF-8 byte string.
    - `L`: 32.

 9. Verify that `keyHandle.mac == HMAC-SHA-256(macKey, seedHandle || ecdhePublicKey || rpIdHash)`.
    If not, this `keyHandle` was generated for a different authenticator. Return CTAP2_ERR_X.

10. Let `p = credKey + s` in the scalar field of `crv`.

11. Set the extension output `sig` to a signature over `tbs` using private key
    `p` and algorithm `alg`. `sig` is DER encoded as described in [RFC 3279][rfc3279].
    
    ISSUE: Not always DER encoding for every `alg`?

`sign` output:
```js
authData.extensions: {
    arkg: {
        sig: BufferSource,
    },
},
```


### Perform Diffie-Hellman exchange

`ecdh` input:
```js
extensions: {
    arkg: {
        ecdh: {
            publicKey: BufferSource,           // ECDH public key for key exchange
            keyHandle: {
                seedHandle:     BufferSource,  // seedHandle from createSeed output
                ecdhePublicKey: BufferSource,  // `E` field of `cred` parameter of DeriveSK in ARKG
                mac:            BufferSource,  // `µ` field of `cred` parameter of DeriveSK in ARKG
            },
        },
    },
},
```

Authenticator processing steps:

 1. Decode the authenticator-specific encoding of `seedHandle` to extract the
    `alg`, `salt`, `uv` and `usage` values. This procedure SHOULD verify
    integrity to ensure that `seedHandle` was generated by this authenticator.

    One possible implementation, compatible with the example encoding described above for `createSeed`, is as follows:

     1. Let `seedMacKey` be a per-credential authenticator secret.

     2. Let `mac = LEFT(32, seedHandle)` and `seedHandleParams = DROP_LEFT(32, seedHandle)`.

     3. Verify that `mac == HMAC-SHA-256(seedMacKey, seedHandleParams || rpIdHash)`. If
        not, this `seedHandle` was generated by a different authenticator. Return CTAP2_ERR_X.

     4. Parse `[alg, salt, uv, usage] = seedHandleParams` as CBOR.
     
     5. Return `(alg, salt, uv, usage`).

    `alg` MUST be a fully-specified COSEAlgorithmIdentifier with a single valid corresponding curve `crv`.
    Let `crv` be this curve.

 2. If `usage` does not include `"ecdh"`, return CTAP2_ERR_X.
    
 3. Use `salt`, `uv` and a per-credential authenticator secret as the seed to
    deterministically regenerate the EC key pair `s, S` on the curve `crv`.

 4. Let `E` be the public key on the curve `crv` decoded from the uncompressed
    point `keyHandle.ecdhePublicKey` as described in [SEC 1][sec1], section
    2.3.4. If invalid, return CTAP2_ERR_X.
    
    ISSUE: Should `E` use COSE_Key format instead of SEC1?

 5. If `E` is the point at infinity, return CTAP2_ERR_X.

 6. Let `ikm = ECDH(s, E)`. Let `ikm_x` be the X coordinate of `ikm`, encoded as
    a byte string of length 32 as described in [SEC 1][sec1], section 2.3.7.

 7. Let `credKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf]
    with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.arkg.ecdh.cred_key` encoded as a UTF-8 byte string.
    - `L`: 32.

    Parse `credKey` as a big-endian unsigned number in the scalar field of `crv`.
    If `credKey` is greater than the order of the curve `crv`, return CTAP2_ERR_X.

 8. Let `macKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf]
    with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.arkg.ecdh.mac_key` encoded as a UTF-8 byte string.
    - `L`: 32.

 9. Verify that `keyHandle.mac == HMAC-SHA-256(macKey, ecdhePublicKey ||
    rpIdHash)`. If not, this `keyHandle` was generated for a different
    authenticator. Return CTAP2_ERR_X.

10. Let `p = credKey + s` in the scalar field of `crv`.

11. Set the extension output `o` to the result of an ECDH exhange between `p` and `publicKey`.

    ISSUE: What is a suitable reference for a spec of an ECDH algorithm?

`ecdh` output:
```js
authData.extensions: {
    arkg: {
        okm: BufferSource,
    },
},
```




## RP operations

### Generate ARKG seed

 1. Invoke `navigator.credentials.create()` or `navigator.credentials.get()`
    with the `arkg` extension with a `createSeed` argument as defined above.
    Let `usage` be value of the `createSeed.usage` argument.
    
    Let `credentialId` be the credential ID of the returned credential. Let
    `seedPublicKey` and `seedHandle` be the respective outputs from the
    `arkg` extension.
    
 2. Store `(credentialId, seedPublicKey, seedHandle, usage)` as an ARKG seed in the relevant user account.


### Generate public key

 1. Let `(credentialId, seedPublicKey, seedHandle, usage)` be one of the ARKG seeds stored in the relevant user account.
 
 2. Let `newKeyUsage` be `"sign"` if the generated public key is to be used for signature generation,
    otherwise let `newUsage` be `"ecdh"` if it is to be used for ECDH key agreement.

 3. If `usage` does not include `newKeyUsage`, return an error.
    
 4. Let `S = seedPublicKey`. Let `crv = seedPublicKey.crv`.

 5. Generate an ephemeral EC key pair on the curve `crv`: `e, E`. If `E` is the
    point at infinity, start over from 1.

 6. Let `ikm = ECDH(e, S)`. Let `ikm_x` be the X coordinate of `ikm`, encoded as
    a byte string of length 32 as described in [SEC 1][sec1], section 2.3.7.
    
 7. Destroy the ephemeral private key `e`.

 8. Let `info` be the string `webauthn.arkg.sign.cred_key` if the public key is to be used for signature generation,
    otherwise let `info` be the string `webauthn.arkg.ecdh.cred_key` if the public key is to be used for ECDH key agreement.

 9. Let `credKey` be the 32 bytes of output keying material from
    [HKDF-SHA-256][hkdf] with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.arkg.${newUsage}.cred_key`, with the value of
      `newUsage` substituted for `${newUsage}`, encoded as a UTF-8 byte string.
    - `L`: 32.

    Parse `credKey` as a big-endian unsigned number in the scalar field of `crv`.
    If `credKey` is greater than the order of the curve `crv`, start over from 1.

10. Let `macKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf] with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.arkg.${newUsage}.mac_key`, with the value of
      `newUsage` substituted for `${newUsage}`, encoded as a UTF-8 byte string.
    - `L`: 32.

11. Let `P = (credKey * G) + S`, where * and + are elliptic curve point
    multiplication and addition in the curve group of `crv` and `G` is the
    generator of `crv`.

12. If `P` is the point at infinity, start over from 1.

13. Let `E_enc` be `E` encoded as described in [SEC 1][sec1], section 2.3.3, without point compression.
    
    ISSUE: Should `E_enc` use COSE_Key format instead of SEC1?

14. Let `mac = HMAC-SHA-256(macKey, seedHandle || E_enc || rpIdHash)`.

15. Let `keyHandle` be an object with the structure:

    ````
    keyHandle = {
        seedHandle:     BufferSource = seedHandle,
        ecdhePublicKey: BufferSource = E_enc,
        mac:            BufferSource = mac,
    }
    ````
    
16. Store `(credentialId, P, keyHandle, newUsage)` as a public key in the relevant user account.


[arkg]: https://eprint.iacr.org/2020/1004
[att-cred-data]: https://w3c.github.io/webauthn/#attested-credential-data
[authdata]: https://w3c.github.io/webauthn/#authenticator-data
[ctap2-canon]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
[hkdf]: https://tools.ietf.org/html/rfc5869
[privacy-cons]: https://www.w3.org/TR/2019/WD-webauthn-2-20191126/#sctn-credential-id-privacy-leak
[rfc3279]: https://tools.ietf.org/html/rfc3279.html
[rp-auth-ext-processing]: https://w3c.github.io/webauthn/#sctn-verifying-assertion
[rp-reg-ext-processing]: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
[sec1]: http://www.secg.org/sec1-v2.pdf
