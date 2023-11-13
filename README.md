# DRAFT: `sign` and `keyAgreement` WebAuthn extensions

_NOTE: This is a draft of a work in progress and **not implementation ready**. All parts of this draft are subject to change._

Authors: Emil Lundberg (Yubico)

Closely related previous work:
- Emil Lundberg and Dain Nilsson, "WebAuthn recovery extension". GitHub, 2019-2021. https://github.com/Yubico/webauthn-recovery-extension
- Frymann et al., "Asynchronous Remote Key Generation: An Analysis of Yubico's Proposal for W3C WebAuthn". Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security, 2020. https://doi.org/10.1145/3372297.3417292


## Introduction

These extensions enable Relying Parties to sign arbitrary data and perform key
agreement using public key protocols, such as Diffie-Hellman.
Both extensions also support the [Asynchronous Remote Key Generation
(ARKG)][arkg] protocol, enabling public key generation to be delegated to a
party without giving that party access to any corresponding private keys.


### The ARKG protocol

The ARKG protocol begins with the authenticator emitting a _seed public key_.
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


### Notation

The following notation is used throughout this document:

- The symbol `||` represents byte array concatenation.
- `LEFT(X, n)` is the first `n` bytes of the byte array `X`.
- `DROP_LEFT(X, n)` is the byte array `X` without the first `n` bytes.
- CTAP2_ERR_X represents some not yet specified error code.


## WebAuthn `sign` extension

This extension enables a Relying Party to sign arbitrary data. The signing
public key is not the same as the credential public key.


### Client extension input

```webidl
partial dictionary AuthenticationExtensionsClientInputs {
    SignExtensionInputs sign;
};

dictionary SignExtensionInputs {
    SignExtensionGenerateKeyInputs generateKey;
    SignExtensionSignInputs sign;

    SignExtensionGenerateKeyInputs arkgGenerateSeed;
    SignExtensionArkgSignInputs arkgSign;
};

dictionary SignExtensionGenerateKeyInputs {
    required sequence<PublicKeyCredentialParameters> pubKeyCredParams;

    SignExtensionKeyUsageRequirement userVerification = "discouraged";
    SignExtensionKeyUsageRequirement backupEligible   = "indifferent";
}

enum SignExtensionOptionRequirement {
    "forbidden",    // CBOR 0
    "discouraged",  // CBOR 1
    "indifferent",  // CBOR 2
    "preferred",    // CBOR 3
    "required",     // CBOR 4
}

dictionary SignExtensionSignInputs {
    required BufferSource tbs;                              // Data to be signed
    record<USVString, BufferSource> keyHandleByCredential;  // Keys from which to choose one to sign with
}

dictionary SignExtensionArkgSignInputs {
    required BufferSource tbs;                                                     // Data to be signed
    required record<USVString, SignExtensionArkgKeyHandle> keyHandleByCredential;  // Keys from which to choose one to sign with
}

dictionary SignExtensionArkgKeyHandle {
    required BufferSource seedHandle;      // seedHandle from createSeed output
    required BufferSource ecdhePublicKey;  // `E` field of `cred` parameter of DeriveSK in ARKG
    required BufferSource mac;             // `µ` field of `cred` parameter of DeriveSK in ARKG
}
```

### Client extension processing

TODO: Translate the extension input to CBOR. Translate the authenticator extension output from CBOR.

TODO: If `generateKey` or `arkgGenerateSeed` is present, use the
`userVerification` and `backupEligible` values to help the user select a
suitable authenticator. Set the `genKey.up` or `arkgGen.up` authenticator
extension input to 4 (required).


### Client extension output

```webidl
partial dictionary AuthenticationExtensionsClientOutputs {
    SignExtensionOutputs sign;
};

dictionary SignExtensionOutputs {
    ArrayBuffer publicKey;
    ArrayBuffer keyHandle;

    ArrayBuffer seedPublicKey;
    ArrayBuffer seedHandle;

    ArrayBuffer signature;
};
```


### Authenticator extension input

```cddl
$$extensionInput //= (
  sign: signExtensionInputs,
)

signExtensionInputs = {
    genKey: signExtensionGenerateKeyInputs,
    ? sign: signExtensionSignInputs,
    //
    arkgGen: signExtensionGenerateKeyInputs,
    ? arkgSign: signExtensionArkgSignInputs,
};

signExtensionSignInputs = {
    tbs: bstr,
    ? kh: { + bstr => bstr },  // Keys from which to choose one to sign with
}

signExtensionOptionRequirement = 0..4

signExtensionGenerateKeyInputs = {
    alg: [+ COSEAlgorithmIdentifier],
    ? up: signExtensionOptionRequirement .default 4,  // Default: "required"
    ? uv: signExtensionOptionRequirement .default 1,  // Default: "discouraged"
    ? be: signExtensionOptionRequirement .default 2,  // Default: "indifferent"
}

signExtensionArkgKeyHandle = {
    sh: bstr;   // seedHandle from createSeed output
    epk: bstr;  // `E` field of `cred` parameter of DeriveSK in ARKG
    mac: bstr;  // `µ` field of `cred` parameter of DeriveSK in ARKG
}

signExtensionArkgSignInputs = {
    tbs: bstr;                                     // Data to be signed
    kh: { + bstr => signExtensionArkgKeyHandle },  // Keys from which to choose one to sign with
}
```


### Authenticator processing steps

 1. If none of `genKey`, `sign`, `arkgGen` or `arkgSign` is present, return CTAP2_ERR_X.

 1. If `genKey` is present:
    1. If the current operation is not an `authenticatorMakeCredential` operation, return CTAP2_ERR_X.

    1. If `arkgGen` or `arkgSign` is present, return CTAP2_ERR_X.

    1. Let `alg` be the authenticator's choice of one of the algorithms listed in `genKey.alg`.

    1. If `alg` is not valid for signature operations, return CTAP2_ERR_X.

    1. Return CTAP2_ERR_X if any of the following is true:
        - `genKey.up` is 0 and this authenticator always requires user presence.
        - `genKey.up` is 5 and this authenticator is not capable of a test of user presence.
        - `genKey.uv` is 0 and this authenticator always requires user verification.
        - `genKey.uv` is 5 and this authenticator is not capable of user verification.
        - `genKey.be` is 0 and this authenticator can only create backup eligible credentials.
        - `genKey.be` is 5 and this authenticator is not capable of creating backup eligible credentials.

    1. Let `up` be a Boolean value as follows.

        - If `genKey.up` is 0, let `up` be `false`.
        - If `genKey.up` is 1, let `up` be `true` if and only if this authenticator always requires user presence.
        - If `genKey.up` is 2, let `up` be `false` or `true` as chosen by the authenticator.
        - If `genKey.up` is 3, let `up` be `true` if and only if this authenticator is capable of a test of user presence.
        - If `genKey.up` is 4, let `up` be `true`.

        Let `uv` and `be` be Boolean values determined in the same way. TODO: Formalize logic for UV and BE.

    1. Use `up`, `uv`, `be` and a per-credential authenticator secret as the
        seeds to deterministically generate a new signing key pair with private
        key `p` and public key `P`.

    1. Let `P_enc` be `P` encoded in COSE_Key format.

    1. Let `keyHandle` be an authenticator-specific encoding of `alg`, `up`,
         `uv` and `be`, which the authenticator can later use to derive the same
         key pair `p, P`. The encoding SHOULD include integrity protection to
         ensure that a given `keyHandle` is valid for a particular
         authenticator.

        One possible implementation is as follows:

        1. Let `macKey` be a per-credential authenticator secret.

        1. Let `keyHandleParams = [alg, up, uv, be]` as CBOR.

        1. Let `keyHandle = HMAC-SHA-256(macKey, keyHandleParams || UTF8Encode("sign") || rpIdHash) || keyHandleParams`.

    1. Set the extension output `sign.pk` to `P_enc`. Set the extension output `sign.kh` to `keyHandle`.

        TODO: Generate attestation containing `up`, `uv` and `be`


 1. If `sign` is present:
    1. If `arkgGen` or `arkgSign` is present, return CTAP2_ERR_X.

    1. If `genKey` is present:

        1. Let `keyHandle` be the value of the `sign.kh` extension output.

        Otherwise:

        1. If `allowCredentials` is empty, return CTAP2_ERR_X.

        1. Let `credentialId` be the credential ID of the credential being used for this assertion.
            Let `keyHandle` be `sign.kh[credentialId]`.

    1. If `keyHandle` is null or undefined, return CTAP2_ERR_X.

    1. Decode the authenticator-specific encoding of `keyHandle` to extract the
        `alg`, `up`, `uv` and `be` values. This procedure SHOULD verify
        integrity to ensure that `keyHandle` was generated by this
        authenticator.

        One possible implementation, compatible with the example encoding
        described in the `genKey` operation, is as follows:

        1. Let `macKey` be a per-credential authenticator secret.

        1. Let `mac = LEFT(32, keyHandle)` and `keyHandleParams = DROP_LEFT(32, keyHandle)`.

        1. Verify that `mac == HMAC-SHA-256(macKey, keyHandleParams ||
            UTF8Encode("sign") || rpIdHash)`. If not, this `keyHandle` was
            generated by a different authenticator. Return CTAP2_ERR_X.

        1. Parse `[alg, up, uv, be] = keyHandleParams` as CBOR.

        1. Return `(alg, up, uv, be)`.

        `alg` MUST be a fully-specified COSEAlgorithmIdentifier.

    1. Use `up`, `uv`, `be` and a per-credential authenticator secret as the
        seeds to deterministically regenerate the signing key pair with private
        key `p` and public key `P`.

    1. Let `sig` be a signature over `tbs` using private key `p` and algorithm
        `alg`.

    1. Set the extension output `sign.sig` to `sig`. Return the extension output.


 1. If `arkgGen` is present:
    1. If the current operation is not an `authenticatorMakeCredential` operation, return CTAP2_ERR_X.

    1. If `genKey`, `sign` or `arkgSign` is present, return CTAP2_ERR_X.

    1. Let `alg` be the authenticator's choice of one of the algorithms listed in `arkgGen.alg`.
        `alg` MUST be a fully-specified COSEAlgorithmIdentifier with a single valid corresponding curve `crv`.
        Let `crv` be this curve.
        If none is supported, return CTAP2_ERR_X.

        ISSUE: Support non-EC algorithms too? ARKG can in principle work with any
        discrete logarithm problem, and post-quantum extensions also exist.

    1. If `crv` is not valid for signature operations, return CTAP2_ERR_X.

        Note: For example, COSE elliptic curve `4` (X25519) is valid for use with ECDH only.

    1. Return CTAP2_ERR_X if any of the following is true:
        - `arkgGen.up` is 0 and this authenticator always requires user presence.
        - `arkgGen.up` is 5 and this authenticator is not capable of a test of user presence.
        - `arkgGen.uv` is 0 and this authenticator always requires user verification.
        - `arkgGen.uv` is 5 and this authenticator is not capable of user verification.
        - `arkgGen.be` is 0 and this authenticator can only create backup eligible credentials.
        - `arkgGen.be` is 5 and this authenticator is not capable of creating backup eligible credentials.

    1. Let `up` be a Boolean value as follows.

        - If `arkgGen.up` is 0, let `up` be `false`.
        - If `arkgGen.up` is 1, let `up` be `true` if and only if this authenticator always requires user presence.
        - If `arkgGen.up` is 2, let `up` be `false` or `true` as chosen by the authenticator.
        - If `arkgGen.up` is 3, let `up` be `true` if and only if this authenticator is capable of a test of user presence.
        - If `arkgGen.up` is 4, let `up` be `true`.

        Let `uv` and `be` be Boolean values determined in the same way. TODO: Formalize logic for UV and BE.

    1. Use `up`, `uv`, `be` and a per-credential authenticator secret as the
        seeds to deterministically generate a new EC key pair `s, S` on the
        curve `crv`.

    1. Let `S_enc` be `S` encoded in COSE_Key format.

    1. Let `seedHandle` be an authenticator-specific encoding of `crv`, `up`,
         `uv` and `be`, which the authenticator can later use to derive the same
         EC key pair `s, S`. The encoding SHOULD include integrity protection to
         ensure that a given `seedHandle` is valid for a particular
         authenticator.

        One possible implementation is as follows:

        1. Let `seedMacKey` be a per-credential authenticator secret.

        1. Let `seedHandleParams = [alg, up, uv, be]` as CBOR.

        1. Let `seedHandle = HMAC-SHA-256(seedMacKey, seedHandleParams || UTF8Encode("sign") || rpIdHash) || seedHandleParams`.

    1. Return `{ spk: S_enc, sh: seedHandle }` as the `sign` extension output.

        TODO: Generate attestation containing `up`, `uv` and `be`

 1. If `arkgSign` is present:
    1. If the current operation is not an `authenticatorGetAssertion` operation, return CTAP2_ERR_X.

    1. If `genKey` or `sign` is present, return CTAP2_ERR_X.

    1. Let `credentialId` be the credential ID of the credential being used for this assertion.
       Let `keyHandle` be `arkgSign.kh[credentialId]`.
       If `keyHandle` is null or undefined, return CTAP2_ERR_X.

    1. Perform the internal operation _derive ARKG private key_ with `keyHandle` as the argument.

        Let `p` be the returned private key. If the operation returned an error,
        instead return that error and terminate these processing steps.

    1. Let `sig` be a signature over `tbs` using private key `p` and algorithm
        `alg`. `sig` is DER encoded as described in [RFC 3279][rfc3279].

        ISSUE: Not always DER encoding for every `alg`?

    1. Return `{ sig: sig }` as the `sign` extension output.


#### Internal operation: derive ARKG private key

This operation is internal to the authenticator, and takes one parameter
`keyHandle` of type `SignExtensionArkgKeyHandle`.

The operation returns a private key `p` or an error.

 1. Decode the authenticator-specific encoding of `seedHandle` to extract the
    `alg`, `up`, `uv` and `be` values. This procedure SHOULD verify integrity to
    ensure that `seedHandle` was generated by this authenticator.

    One possible implementation, compatible with the example encoding described in the `arkgGenerateSeed` operation, is as follows:

     1. Let `seedMacKey` be a per-credential authenticator secret.

     1. Let `mac = LEFT(32, seedHandle)` and `seedHandleParams = DROP_LEFT(32, seedHandle)`.

     1. Verify that `mac == HMAC-SHA-256(seedMacKey, seedHandleParams ||
        UTF8Encode("sign") || rpIdHash)`. If not, this `seedHandle` was
        generated by a different authenticator. Return CTAP2_ERR_X.

     1. Parse `[alg, up, uv, be] = seedHandleParams` as CBOR.

     1. Return `(alg, up, uv, be)`.

    `alg` MUST be a fully-specified COSEAlgorithmIdentifier with a single valid corresponding curve `crv`.
    Let `crv` be this curve.
    Let `crvOL` be the byte length of the order of the `crv` group.
    Let `crvSL` be the byte length of the scalar field of `crv`.

 1. Use `up`, `uv`, `be` and a per-credential authenticator secret as the seeds
    to deterministically regenerate the EC key pair `s, S` on the curve `crv`.

 1. Let `E` be the public key on the curve `crv` decoded from the uncompressed
    point `keyHandle.ecdhePublicKey` as described in [SEC 1][sec1], section
    2.3.4. If invalid, return CTAP2_ERR_X.

    ISSUE: Should `E` use COSE_Key format instead of SEC1?

 1. If `E` is the point at infinity, return CTAP2_ERR_X.

 1. Let `ikm = ECDH(s, E)`. Let `ikm_x` be the X coordinate of `ikm`, encoded as
    a byte string of length `crvSL` as described in [SEC 1][sec1], section 2.3.7.

 1. Let `credKey` be the `crvOL` bytes of output keying material from [HKDF-SHA-256][hkdf]
    with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.sign.arkg.cred_key`, encoded as a UTF-8 byte string.
    - `L`: `crvOL`.

    Parse `credKey` as a big-endian unsigned number in the scalar field of `crv`.
    If `credKey` is greater than the order of the curve `crv`, return CTAP2_ERR_X.

 1. Let `macKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf]
    with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.sign.arkg.mac_key`, encoded as a UTF-8 byte string.
    - `L`: 32.

 1. Verify that `keyHandle.mac == HMAC-SHA-256(macKey, seedHandle || ecdhePublicKey || rpIdHash)`.
    If not, this `keyHandle` was generated for a different authenticator. Return CTAP2_ERR_X.

 1. Let `p = credKey + s` in the scalar field of `crv`.

 1. Return `p`.


### Authenticator extension output

```cddl
$$extensionOutput //= (
    sign: signExtensionOutputs,
)

signExtensionOutputs = {
    pk: bstr,
    kh: bstr,
    ? sig: bstr,

    //

    spk: bstr,
    sh: bstr,

    //

    sig: bstr,
},
```

TODO: attestation


### RP operations

#### Generate ARKG seed

 1. Invoke `navigator.credentials.create()` or `navigator.credentials.get()`
    with the `sign` extension with a `arkgGenerateSeed` argument as defined above.

    Let `credentialId` be the credential ID of the returned credential. Let
    `seedPublicKey` and `seedHandle` be the respective outputs from the `sign`
    extension.

 1. Store `(credentialId, seedPublicKey, seedHandle)` as an ARKG seed for signing in the relevant user account.


#### Generate public key

 1. Let `(credentialId, seedPublicKey, seedHandle)` be one of the ARKG seeds stored in the relevant user account.

 1. Let `S = seedPublicKey`. Let `crv = seedPublicKey.crv`.
    Let `crvOL` be the byte length of the order of the `crv` group.
    Let `crvSL` be the byte length of the scalar field of `crv`.

 1. Generate an ephemeral EC key pair on the curve `crv`: `e, E`. If `E` is the
    point at infinity, start over from 1.

 1. Let `ikm = ECDH(e, S)`. Let `ikm_x` be the X coordinate of `ikm`, encoded as
    a byte string of length `crvSL` as described in [SEC 1][sec1], section 2.3.7.

 1. Destroy the ephemeral private key `e`.

 1. Let `credKey` be the `crvOL` bytes of output keying material from
    [HKDF-SHA-256][hkdf] with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.sign.arkg.cred_key`, encoded as a UTF-8 byte string.
    - `L`: `crvOL`.

    Parse `credKey` as a big-endian unsigned number in the scalar field of `crv`.
    If `credKey` is greater than the order of the curve `crv`, start over from 1.

 1. Let `macKey` be the 32 bytes of output keying material from [HKDF-SHA-256][hkdf] with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.sign.arkg.mac_key`, encoded as a UTF-8 byte string.
    - `L`: 32.

 1. Let `P = (credKey * G) + S`, where * and + are elliptic curve scalar
    multiplication and point addition in the `crv` group and `G` is the group
    generator.

 1. If `P` is the point at infinity, start over from 1.

 1. Let `E_enc` be `E` encoded as described in [SEC 1][sec1], section 2.3.3, without point compression.

    ISSUE: Should `E_enc` use COSE_Key format instead of SEC1?

 1. Let `mac = HMAC-SHA-256(macKey, seedHandle || E_enc || rpIdHash)`.

 1. Let `keyHandle` be an object with the structure:

    ````
    keyHandle = {
        seedHandle:     BufferSource = seedHandle,
        ecdhePublicKey: BufferSource = E_enc,
        mac:            BufferSource = mac,
    }
    ````

 1. Store `(credentialId, P, keyHandle)` as a public key for signing in the relevant user account.


## WebAuthn `keyAgreement` extension

TODO: Spell out the whole extension once details are settled.

Analogous to the `sign` extension, but outputting the result of a Diffie-Hellman
exchange instead of a signature. Inputs change like this:


```webidl
dictionary KeyAgreementExtensionInputs {
    SignExtensionGenerateKeyInputs generateKey;
    KeyAgreementExtensionDhInputs dh;

    SignExtensionGenerateKeyInputs arkgGenerateSeed;
    SKeyAgreementExtensioArkgEcdhInputs arkgEcdh;
};

dictionary KeyAgreementExtensionDhInputs {
    required BufferSource publicKey;  // Public key for Diffie-Hellman key agreement
    required BufferSource keyHandle;  // Private key handle for Diffie-Hellman key agreement
}

dictionary KeyAgreementExtensionArkgEcdhInputs {
    required BufferSource publicKey;                                               // Public key for ECDH key agreement
    required record<USVString, SignExtensionArkgKeyHandle> keyHandleByCredential;  // Private key handles for ECDH key agreement
}
```

and outputs like this:

```webidl
partial dictionary AuthenticationExtensionsClientOutputs {
    KeyAgreementExtensionOutputs keyAgreement;
};

dictionary KeyAgreementExtensionOutputs {
    ArrayBuffer publicKey;
    ArrayBuffer keyHandle;

    ArrayBuffer seedPublicKey;
    ArrayBuffer seedHandle;

    ArrayBuffer okm;
};
```

```cddl
$$extensionOutput //= (
    keyAgreement: keyAgreementExtensionOutputs,
)

keyAgreementExtensionOutputs = {
    pk: bstr,
    kh: bstr,
    ? okm: bstr,

    //

    spk: bstr,
    sh: bstr,

    //

    okm: bstr,
},
```

and the last step of the `dh` and `arkgEcdh` authenticator operations is:

 1. Set the extension output `okm` to the result of an ECDH exhange between `p` and `[dh | arkgEcdh].publicKey`.

    ISSUE: What is a suitable reference for a spec of an ECDH algorithm?

and the HKDF `info` arguments used in _derive ARKG private key_ are
`webauthn.keyAgreement.arkg.cred_key` and `webauthn.keyAgreement.arkg.cred_key`.


RP operations are also the same, except the ARKG seed and generated public keys
are key agreement keys instead of signing keys.


[arkg]: https://doi.org/10.1145/3372297.3417292
[att-cred-data]: https://w3c.github.io/webauthn/#attested-credential-data
[authdata]: https://w3c.github.io/webauthn/#authenticator-data
[ctap2-canon]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
[hkdf]: https://tools.ietf.org/html/rfc5869
[privacy-cons]: https://www.w3.org/TR/2019/WD-webauthn-2-20191126/#sctn-credential-id-privacy-leak
[rfc3279]: https://tools.ietf.org/html/rfc3279.html
[rp-auth-ext-processing]: https://w3c.github.io/webauthn/#sctn-verifying-assertion
[rp-reg-ext-processing]: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
[sec1]: http://www.secg.org/sec1-v2.pdf
