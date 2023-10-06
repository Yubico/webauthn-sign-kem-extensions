


`createSeed` input:
```js
extensions: {
    arkgSign: {
        createSeed: {
            pubKeyCredParams: [
                { type: "public-key", alg: -7 }, // ES256
                { type: "public-key", alg: -8 }, // Ed25519
            ],
            salt: new Uint8Array([1, 2, 3, 4]),
        },
    },
},
```

Authenticator processing steps:

 1. Let `crv` be the authenticator's choice of one of the curves listed in `pubKeyCredParams`.

 2. Use `salt` and a per-credential authenticator secret as the seed to deterministically generate
    a new EC key pair `s, S` on the curve `crv`.

 3. Let `S_enc` be `S` encoded as described in [SEC 1][sec1], section 2.3.3, without point compression.

 4. Let `seedMacKey` be a per-credential authenticator secret.

 5. Let `seedHandleTbs = [crv, salt]` as CBOR.

 6. Let `seedHandle = HMAC-SHA-256(seedMacKey, seedHandleTbs || rpIdHash) || seedHandleTbs`.

 7. Return `seedPublicKey: S` and `seedHandle: seedHandle`.


`createSeed` output:
```js
authData.extensions: {
    arkgSign: {
        seedPublicKey: ArrayBuffer,  // ARKG public key seed in COSE_Key format
        seedHandle: ArrayBuffer,     // Private seed re-derivation parameters for the authenticator (will include salt and curve ID)
    },
},
```

Holder of `seedPublicKey` can now generate public keys on behalf of the authenticator:

 1. Let `S = seedPublicKey`. Let `crv = seedPublicKey.crv`.

 2. Generate an ephemeral EC key pair on the curve `crv`: `e, E`. `E` MUST NOT be the point at infinity.

 3. Let `ikm = ECDH(e, S)`. Let `ikm_x` be the X coordinate of `ikm`, encoded as
    a byte string of length 32 as described in [SEC 1][sec1], section 2.3.7.

 4. Let `credKey` be the 32 bytes of output keying material from
    [HKDF-SHA-256][hkdf] with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.recovery.cred_key` encoded as a UTF-8 byte string.
    - `L`: 32.

    Parse `credKey` as a big-endian unsigned 256-bit number.

 5. Let `macKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf] with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.recovery.mac_key` encoded as a UTF-8 byte string.
    - `L`: 32.

 6. If `credKey >= n`, where `n` is the order of `crv`, start over from 1.

 7. Let `P = (credKey * G) + S`, where * and + are EC point multiplication and addition,
    and `G` is the generator of the curve `crv`.

 8. If `P` is the point at infinity, start over from 1.

 9. Let `rpIdHash` be the SHA-256 hash of `rpId`.

10. Let `E_enc` be `E` encoded as described in [SEC 1][sec1], section 2.3.3, without point compression.

11. Set `keyHandleTbs = E_enc` as CBOR.

12. Set `keyHandle = HMAC-SHA-256(macKey, keyHandleTbs || rpIdHash) || keyHandleTbs`.


`sign` input:
```js
extensions: {
    arkgSign: {
        sign: {
            seedHandle: BufferSource,  // seedHandle from createSeed output
            keyHandle: BufferSource,   // ARKG `cred` parameter for private key derivation
            tbs: BufferSource,         // Data to sign
        },
    },
},
```

Authenticator processing steps:

 1. Let `E_enc = LEFT(DROP_LEFT(cred.id, 1), 65)`.

 1. Let `E` be the P-256 public key decoded from the uncompressed point
  `E_enc` as described in [SEC 1][sec1], section 2.3.4. If invalid,
  return CTAP2_ERR_XXX.

 1. If `E` is the point at infinity, return CTAP2_ERR_XXX.

 1. Let `ikm = ECDH(s, E)`. Let `ikm_x` be the X coordinate of `ikm`,
  encoded as a byte string of length 32 as described in
  [SEC 1][sec1], section 2.3.7.

 1. Let `credKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf]
  with the arguments:

  - `salt`: Not set.
  - `IKM`: `ikm_x`.
  - `info`: The string `webauthn.recovery.cred_key` encoded as a UTF-8 byte string.
  - `L`: 32.

  Parse `credKey` as a big-endian unsigned 256-bit number.

 1. Let `macKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf]
  with the arguments:

  - `salt`: Not set.
  - `IKM`: `ikm_x`.
  - `info`: The string `webauthn.recovery.mac_key` encoded as a UTF-8 byte string.
  - `L`: 32.

 1. Let `rpIdHash` be the SHA-256 hash of `rp.id`.

 1. If `cred.id` is not exactly equal to `alg || E || LEFT(HMAC-SHA-256(macKey, alg
  || E || rpIdHash), 16)`, _continue_.

 1. Let `p = credKey + s (mod n)`, where `n` is the order of the P-256
  curve.

 1. Let `authenticatorDataWithoutExtensions` be the [authenticator
  data][authdata] that will be returned from this registration operation,
  but without the `extensions` part. The `ED` flag in
  `authenticatorDataWithoutExtensions` MUST be set to 1 even though
  `authenticatorDataWithoutExtensions` does not include extension data.

 1. Let `sig` be a signature over `authenticatorDataWithoutExtensions ||
  clientDataHash` using `p`. `sig` is DER encoded as described in [RFC
  3279][rfc3279].

`sign` output:
```js
authData.extensions: {
    arkgSign: {
        sig: BufferSource,
    },
},
```
