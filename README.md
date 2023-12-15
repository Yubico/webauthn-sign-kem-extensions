# DRAFT: `sign` and `kem` WebAuthn extensions

_NOTE: This is a draft of a work in progress and **not implementation ready**.
All parts of this draft are subject to change._

Authors: Emil Lundberg (Yubico)

Closely related previous work:
- Emil Lundberg and Dain Nilsson, "WebAuthn recovery extension". GitHub, 2019-2021.
  https://github.com/Yubico/webauthn-recovery-extension
- Frymann et al., "Asynchronous Remote Key Generation: An Analysis of Yubico's Proposal for W3C WebAuthn".
  Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security, 2020.
  https://doi.org/10.1145/3372297.3417292


## Introduction

These extensions enable Relying Parties to sign arbitrary data
and use key encapsulation mechanisms (KEM) using public key protocols.
Both extensions also support the [Asynchronous Remote Key Generation (ARKG)][arkg] protocol,
enabling public key generation to be delegated to a party without giving that party access to any corresponding private keys.


### The ARKG protocol

The ARKG protocol begins with the authenticator emitting a _seed public key_.
The Relying Party can use the seed public key to generate any number of _derived public keys_,
but the Relying Party does not gain access to the corresponding private keys.
Derived public keys on their own are unlinkable;
given two derived public keys it is impossible to determine
whether they were derived from the same seed public key or were generated independently.

Finally, the Relying Party can request two operations from the authenticator:

- Given a derived public key _P_, derive the private key _p_
  corresponding to _P_ and generate a signature using _p_.

  This enables the Relying Party to sign arbitrary data using public keys
  that can be generated in advance without access to the authenticator.
  For example, this could be used in scenarios
  where each signature uses a unique public key to prevent tracking,
  where many public keys could be generated in advance for later offline use.

- Given a derived public key _P_ and an ephemeral public key _E_,
  derive the private key _p_ corresponding to _P_
  and perform a Diffie-Hellman exchange between _p_ and _E_.

  This gives the Relying Party access to a random oracle similar to the `prf` extension,
  but with the difference that a shared secret can be initially generated
  without access to the authenticator.
  For example, this can be used as a key encapsulation mechanism (KEM)
  where the authenticator needs to be present only during decryption.


### Attestation considerations

#### Traditional public keys

Because the requested number of keys might be too large to fit in client-to-authenticator protocol messages,
one key generation request at the WebAuthn layer might need to be implemented via a batch of multiple authenticator operations.
This also means that the authenticator extension outputs at the WebAuthn layer
might not include all of the public keys returned in the client extension outputs.
For these reasons the generated public keys are conveyed primarily via client extension outputs,
and when the RP requests attestation, a unique attestation signature is generated for each generated public key.
These attestation signatures are distinct from the top-level attestation statement,
and sign of over different signed data.

TODO: Figure out further details and expand this section


#### ARKG seed public keys

The ARKG seed public keys generated by these extensions are covered by any attestation returned during the registration ceremony.
The RP's requirements on user verification and backup eligibility are set during the registration ceremony,
and are immutable for the lifetime of each key.
Thus the RP can determine whether its requirements are satisfied
by inspecting the attestation statement and the authenticator data flags.

Each WebAuthn credential corresponds to at most one signing seed public key
and at most one KEM seed public key.
If a RP requires keys with varying user verification or backup eligibility properties,
the RP must create a unique key - and thus a unique WebAuthn credential - for each such setting.
These extensions do not require any state to be stored in the authenticator,
and therefore work with non-discoverable keys as well as discoverable keys.


#### Attestation for ARKG public keys

Public keys generated using ARKG are generated by the RP rather than by the authenticator,
although the authenticator keeps exclusive control of the corresponding private keys.
This means that attestation interacts differently with ARKG public keys than with ordinary public keys.

The attestation statement from the registration ceremony covers the ARKG seed public key.
The attestation should be understood as applying to any public keys derived from the seed public key,
but the attestation statement cannot be directly verified against a derived public key.
Instead, the attestation verifier can verify that a public key `P` was derived
from a given ARKG seed public key `S` if the attestation verifier gets access to the key handle of `P`
and the ephemeral private key `e` used to generate `P`.
The simplest way to achieve this is if the attestation verifier is itself the party that generates `P`.
Knowing that `P` was generated using ARKG from the seed public key `S`,
the attestation verifier can conclude that only the holder of the corresponding seed private key - i.e.,
the holder of the attestation key - has access to the private key corresponding to `P`.

Signature verifiers do not need to be aware of ARKG
if they only need to verify signatures against the public key `P` and do not need attestation,
or if they rely on a trusted external party to verify the attestation for `P`.


### Considerations for discoverable keys

Although these extensions may be used with discoverable keys,
they do not support usage with an empty `allowCredentials`, for the following reasons:

- The `sign` extension may be used to sign arbitrary data, but its intended use is for signing data that is meaningful on its own.
  This is unlike a random authentication challenge, which may be meaningless on its own
  and is used only to guarantee that an authentication signature was generated recently.
  In order to sign meaningful data, the RP must first know what is to be signed,
  and thus presumably must also first know which key is to be used for signing.
  Thus, the signing use case is largely incompatible with the anonymous authentication challenge use case.

- The `kem` extension may be used to derive encryption keys,
  but in order to do so the RP needs to supply the key derivation parameters
  for the ciphertext in question.

  For example, say an RP wishes to allow a user to log in
  and immediately decrypt a ciphertext downloaded from the user's account.
  The RP does not know which ciphertext is to be decrypted before the user is identified,
  and thus cannot diversify the key derivation parameters by ciphertext or even by user.
  The RP would have to use the same KEM keypair for _all_ key derivations,
  and could not feasibly replace this key.
  The encryption could not be done on the client side,
  since the RP's shared KEM private key would enable any user to decrypt any other user's ciphertexts.
  Thus it would be better for that RP to use server-side access control instead.

In conclusion: the RP almost certainly needs to identify the user
before performing a signing or KEM operation,
by the nature of these operations.
Thus the restriction to non-empty `allowCredentials`
is unlikely to impose any additional restriction in practice,
but does enable support for stateless authenticator implementations.


### Notation

The following notation is used throughout this document:

- The symbol `||` represents byte array concatenation.
- `LEFT(X, n)` is the first `n` bytes of the byte array `X`.
- `DROP_LEFT(X, n)` is the byte array `X` without the first `n` bytes.
- CTAP2_ERR_X represents some not yet specified error code.


## WebAuthn `sign` extension

This extension enables a Relying Party to sign arbitrary data.
The signing public key is not the same as the credential public key.


### Client extension input

```webidl
partial dictionary AuthenticationExtensionsClientInputs {
    AuthenticationExtensionsSignInputs sign;
}

dictionary AuthenticationExtensionsSignInputs {
    AuthenticationExtensionsSignGenerateKeyInputs arkgGenerateSeed;
    AuthenticationExtensionsSignArkgSignInputs arkgSign;

    AuthenticationExtensionsSignGenerateKeyInputs generateKey;
    AuthenticationExtensionsSignSignInputs sign;
}
```

- `arkgGenerateSeed`

  Inputs for generating an ARKG seed public key.
  Valid only during a registration ceremony.

  If both `arkgGenerateSeed` and `generateKey` are present,
  `arkgGenerateSeed` takes precedence.
  If the authenticator supports ARKG, it will generate an ARKG seed public key;
  otherwise it will generate an ordinary public key.

- `arkgSign`

  Inputs for generating a signature using a private key derived using ARKG.
  Valid only during an authentication ceremony.

  If both `arkgSign` and `sign` are present, `arkgSign` takes precedence.
  If the authenticator supports ARKG and finds a valid signing key handle,
  it will sign using the private key derived from the `arkgSign` inputs;
  otherwise it will use the private key derived from the `sign` inputs.

- `generateKey`

  Inputs for generating a signing public key.
  Valid only during a registration ceremony.

- `sign`

  Inputs for generating a signature.
  MAY be present during both registration and authentication ceremonies.

```
dictionary AuthenticationExtensionsSignGenerateKeyInputs {
    unsigned long numKeys = 1;

    // TODO: Keep some kind of alg for kem extension:    required sequence<PublicKeyCredentialParameters> pubKeyCredParams;
    // TODO: Use credProtect to define UV
    // TODO: Note that unusable resident credentials might be created
}
```

- `pubKeyCredParams`: List of what KEY ENCAPSULATION algorithms the RP supports,
  ordered from most to least preferred.
  The authenticator chooses the most preferred algorithm it supports,
  and returns an error if it supports none of the listed algorithms.

- `numKeys`: The number of key pairs to generate.

```
dictionary AuthenticationExtensionsSignSignInputs {
    required BufferSource tbs;
    record<USVString, BufferSource> keyHandleByCredential;
}
```

Inputs for generating a signature with a previously generated public key,
or a new public key generated and returned along with the signature.

- `tbs`: The data to be signed. Its format may depend on the signature algorithm.

- `keyHandleByCredential`: A record mapping base64url encoded credential IDs
  to signing key handles to use for each credential.
  Only applicable during assertions when `allowCredentials` is not empty.

  This input is OPTIONAL during registration ceremonies if the `generateKey` input is also set,
  and REQUIRED during authentication ceremonies.

```
dictionary AuthenticationExtensionsSignArkgSignInputs {
    required BufferSource tbs;
    required record<USVString, AuthenticationExtensionsSignArkgKeyHandle> keyHandleByCredential;
}
```

Inputs for generating a signature using a private key derived using ARKG.
The corresponding public key is generated by the RP alone
using the procedure defined in the "Generate public key" section of "RP operations".

- `tbs`: The data to be signed. Its format may depend on the signature algorithm.

- `keyHandleByCredential`: A record mapping base64url encoded credential IDs
  to signing key handles to use for each credential.
  Only applicable during assertions when `allowCredentials` is not empty.

  The values for this record are generated using the procedure
  defined in the "Generate public key" section of "RP operations"

```
dictionary AuthenticationExtensionsSignArkgKeyHandle {
    required BufferSource seedHandle;
    required BufferSource ecdhePublicKey;
    required BufferSource mac;
}
```

This structure is one of the outputs of the procedure
defined in the "Generate public key" section of "RP operations".

- `seedHandle`: The `seedHandle` extension output emitted
  during the registration ceremony when the ARKG seed public key was generated.

- `ecdhePublicKey`: The ephemeral Elliptic Curve Diffie-Hellman (ECDHE) public key
  that was used to generate the public key corresponding to this key handle.
  See the "Generate public key" section of "RP operations".

- `mac`: The MAC computed over the rest of the key handle fields
  when generating the public key corresponding to this key handle.
  See the "Generate public key" section of "RP operations".


### Client extension processing

 1. If none of `generateKey`, `sign`, `arkgGenerateSeed` or `arkgSign` is present,
    return a "NotSupportedError" DOMException.

 1. If both `arkgGenerateSeed` and `arkgSign` are present,
    return a DOMException whose name is "NotSupportedError".

 1. Let `extInput` be an empty CBOR map.

 1. If `arkgSign` is present:

    1. If the current ceremony is not an authentication ceremony,
        return a DOMException whose name is "NotSupportedError".

    1. If `arkgSign.keyHandleByCredential` is not present or is empty,
        then return a DOMException whose name is "NotSupportedError".

    1. If any key in `arkgSign.keyHandleByCredential` is the empty string,
        or is not a valid base64url encoding,
        or does not equal the id of some element of `allowCredentials`
        after performing base64url decoding,
        then return a DOMException whose name is "SyntaxError".

 1. If `generateKey` is present:

    1. If the current ceremony is not a registration ceremony,
        return a DOMException whose name is "NotSupportedError".

 1. If `sign` is present:

    1. If the current ceremony is a registration ceremony:

        1. If `generateKey` is not present,
            then return a DOMException whose name is "NotSupportedError".

        1. If `sign.keyHandleByCredential` is present,
            then return a DOMException whose name is "NotSupportedError".

    1. If the current ceremony is an authentication ceremony:

        1. If `sign.keyHandleByCredential` is not present or is empty,
            then return a DOMException whose name is "NotSupportedError".

        1. If any key in `sign.keyHandleByCredential` is the empty string,
            or is not a valid base64url encoding,
            or does not equal the id of some element of `allowCredentials`
            after performing base64url decoding,
            then return a DOMException whose name is "SyntaxError".

 1. If `arkgGenerateSeed` is present:

    1. If the current ceremony is not a registration ceremony,
        return a DOMException whose name is "NotSupportedError".

    1. When selecting the authenticator to use for the ceremony,
        attempt to select one that supports the `sign` extension with ARKG.

    1. (FOR KEM ONLY) If `arkgGenerateSeed.pubKeyCredParams` contains any item
        whose `alg` member's value is not a fully specified COSEAlgorithmIdentifier,
        return a DOMException whose name is "NotSupportedError"

    1. Set `extInput.arkgGen` to a CBOR map with the entries:

        - `alg`: A CBOR array containing the value of the `alg` member
          of each item in `pubKeyCredParams`.

        - `up`: TODO: Encode sensible UP option

        - `uv`: TODO: Encode `authenticatorSelection.userVerification` and/or credProtect

 1. If `arkgSign` is present:

    1. When selecting the authenticator to use for the ceremony,
        attempt to select one that supports the `sign` extension with ARKG.

    1. Set `extInput.arkgSign` to a CBOR map with the entries:

        - `tbs`: The value `arkgSign.tbs` encoded as a CBOR byte string.
        - `kh`: A CBOR map mapping the base64url decoding of each key of
          `arkgSign.keyHandleByCredential` to its corresponding value.

 1. If `generateKey` is present:

    1. If the current ceremony is not a registration ceremony,
        return a DOMException whose name is "NotSupportedError".

    1. (KEM ONLY) If `generateKey.pubKeyCredParams` contains any item
        whose `alg` member's value is not a fully specified COSEAlgorithmIdentifier,
        return a DOMException whose name is "NotSupportedError"

    1. Let `generatedKeys` be an empty list.

    1. While `generatedKeys` has length less than `generateKey.numKeys`:
        1. Let `ikm` be some random input key material.

        1. Let `keyHandle` be an authenticator-specific encoding of `ikm`, `alg`, `up`, `uv` and `be`,
            which the authenticator can later use to derive the same key pair `p, P`.
            The encoding SHOULD include integrity protection
            to ensure that a given `keyHandle` is valid for a particular authenticator.

            One possible implementation is as follows:

            1. Let `macKey` be a per-credential authenticator secret.

            1. Let `keyHandleParams = [alg, up, uv, be]` as CBOR.

            1. Let `keyHandle = HMAC-SHA-256(macKey, keyHandleParams || UTF8Encode("sign") || rpIdHash) || keyHandleParams`.

        1. TODO: BATCH KEY CREATION

        1. Set `extInput.genKey` to a CBOR map with the entries:

            - `alg`: A CBOR array containing the value of the `alg` member
              of each item in `pubKeyCredParams`.

            - `up`: TODO: Encode sensible UP option

            - `uv`: TODO: Encode `authenticatorSelection.userVerification` and/or credProtect

        1. TODO: GET OUTPUT Append `{ pk: P_enc, kh: kh }` to `generatedKeys`.

    1. Set the extension output `sign.pk` to `P_enc`. Set the extension output `sign.kh` to `keyHandle`.

 1. If `sign` is present:

    1. Let `extSignInput` be a new CBOR map.

    1. Set `extSignInput.tbs` to the value of `sign.tbs` encoded as a CBOR byte string.

    1. If `sign.keyHandleByCredential` is present:

        1. Set `extSignInput.kh` to a CBOR map
            mapping the base64url decoding of each key of `sign.keyHandleByCredential`
            to its corresponding value.

    1. Set `extInput.sign` to `extSignInput`.

 1. Set the `sign` extension authenticator input to `extInput`.

 1. TODO: Batch key generations with UP=0,UV=0; parse extension outputs


### Client extension output

```webidl
partial dictionary AuthenticationExtensionsClientOutputs {
    AuthenticationExtensionsSignOutputs sign;
}
```

```webidl
dictionary AuthenticationExtensionsSignOutputs {
    AuthenticationExtensionsSignArkgGenerateSeedOutputs      arkgGenerateSeed;
    sequence<AuthenticationExtensionsSignGenerateKeyOutputs> generateKey;
    ArrayBuffer                                              signature;
}
```

- `arkgGenerateSeed`: The generated ARKG seed public key.
  Present during registration ceremonies,
  if and only if the `arkgGenerateSeed` input was present
  and the authenticator supports ARKG.

- `generateKey`: The generated public keys.
  The length of this sequence equals the `generateKey.numKeys` extension input.
  Present during registration ceremonies,
  if and only if the `generateKey` input was present
  and either the `arkgGenerateSeed` input was not present
  or the authenticator does not support ARKG.

- `signature`: The signature over the input data.
  Present only and always during authentication ceremonies.

```webidl
dictionary AuthenticationExtensionsSignArkgGenerateSeedOutputs {
    required ArrayBuffer seedPublicKey;
    required ArrayBuffer seedHandle;
}
```

- `seedPublicKey`: The generated ARKG seed public key.

- `seedHandle`: The seed handle for the ARKG seed key pair.


```webidl
dictionary AuthenticationExtensionsSignGenerateKeyOutputs {
    required ArrayBuffer publicKey;
    required ArrayBuffer keyHandle;
    ArrayBuffer          attestationSignature;
    ArrayBuffer          okm;
}
```

- `publicKey`: The generated public key, in COSE_Key format.

- `keyHandle`: The key handle of the generated key pair.

- `attestationSignature`: An attestation signature for the generated public key.
  Present only if attestation was requested.
  TODO: Define signing and verification procedures

- `okm`: (Valid only for the `kem` extension)
  The output of a key encapsulation between the public key given as the `kem.decapsulate.publicKey` input
  and the secret key corresponding to the `publicKey` output.
  Present only if the `kem.decapsulate.publicKey` input was present.


### Authenticator extension input

**`sign` extension**:

```cddl
$$extensionInput //= (
  sign: signExtensionInputs,
)

signExtensionInputs = {
    1*2 (
        arkgGen: true,
        //
        genKey: true,
    ),
    //
    1*2 (
        arkgSign: signExtensionArkgSignInputs,
        //
        sign: signExtensionSignInputs,
    ),
}

signExtensionSignInputs = {
    tbs: bstr,
    kh: { + bstr => bstr },
}

signExtensionArkgKeyHandle = {
    sh: bstr,
    epk: bstr,
    mac: bstr,
}

signExtensionArkgSignInputs = {
    tbs: bstr,
    kh: { + bstr => signExtensionArkgKeyHandle },
}
```

**`kem` extension:**

```cddl
$$extensionInput //= (
  kem: kemExtensionInputs,
)

kemExtensionInputs = {
    1*2 (
        arkgGen: kemExtensionGenKeyInputs,
        //
        genKey: kemExtensionGenKeyInputs,
        ? dec: kemExtensionGenKeyDecapsulateInputs,
    ),
    //
    1*2 (
        arkgDec: kemExtensionArkgDecapsulateInputs,
        //
        dec: kemExtensionDecapsulateInputs,
    ),
}

kemExtensionGenKeyInputs = {
    alg: [+ COSEAlgorithmIdentifier],
}

kemExtensionGenKeyDecapsulateInputs = {
    pk: bstr,
}

kemExtensionDecapsulateInputs = {
    pk: bstr,
    ? kh: { + bstr => bstr },
}

kemExtensionArkgKeyHandle = signExtensionArkgKeyHandle

kemExtensionArkgDecapsulateInputs = {
    pk: bstr,
    kh: { + bstr => kemExtensionArkgKeyHandle },
}
```


### Authenticator processing steps

 1. If none of `genKey`, `sign`, `arkgGen` or `arkgSign` is present,
    return CTAP2_ERR_X.

 1. If both `arkgGen` and `arkgSign` are present, return CTAP2_ERR_X.

 1. If `arkgGen` is present and this authenticator supports ARKG:
    1. If the current operation is not an `authenticatorMakeCredential` operation,
        return CTAP2_ERR_X.

    1. (TODO: FOR KEM EXTENSION ONLY) Let `alg` be the authenticator's choice of one of the algorithms listed in `arkgGen.alg`.
        `alg` MUST be a fully-specified COSEAlgorithmIdentifier identifying an ARKG instance. [TODO: Reference ARKG RFC]
        If none is supported, return CTAP2_ERR_X.

    1. (TODO: FOR KEM EXTENSION ONLY)
        If `alg` is not valid for key encapsulation operations, return CTAP2_ERR_X.

        Note: For example, COSE elliptic curve `6` (Ed25519) is valid for use with EdDSA only,
        so an ARKG instance which outputs Ed25519 keys is not eligible for this extension.

    1. TODO: COMPUTE `up`, `uv`, `be`

    1. Use `up`, `uv`, `be` and a per-credential authenticator secret
        as the seeds to deterministically generate a new EC key pair `s, S` on the curve `crv`.

    1. Let `S_enc` be `S` encoded in COSE_Key format.

    1. Let `seedHandle` be an authenticator-specific encoding of `crv`, `up`, `uv` and `be`,
        which the authenticator can later use to derive the same EC key pair `s, S`.
        The encoding SHOULD include integrity protection
        to ensure that a given `seedHandle` is valid for a particular authenticator.

        One possible implementation is as follows:

        1. Let `seedMacKey` be a per-credential authenticator secret.

        1. Let `seedHandleParams = [alg, up, uv, be]` as CBOR.

        1. Let `seedHandle = HMAC-SHA-256(seedMacKey, seedHandleParams || UTF8Encode("sign") || rpIdHash) || seedHandleParams`.

    1. Return `{ spk: S_enc, sh: seedHandle }` as the `sign` extension output
        and terminate these processing steps.

 1. If `arkgSign` is present and this authenticator supports ARKG:
    1. If the current operation is not an `authenticatorGetAssertion` operation,
        return CTAP2_ERR_X.

    1. If `allowCredentials` is empty, return CTAP2_ERR_X.

    1. Let `credentialId` be the credential ID of the credential being used for this assertion.
        Let `keyHandle` be `sign.kh[credentialId]`.

    1. If `keyHandle` is null or undefined, return CTAP2_ERR_X.

    1. Let `seedHandle` be the value of `keyHandle.sh`.

    1. Decode the authenticator-specific encoding of `seedHandle`
        to extract the `alg`, `up`, `uv` and `be` values.
        This procedure SHOULD verify integrity to ensure that `seedHandle` was generated by this authenticator.

        One possible implementation,
        compatible with the example encoding described in the `arkgGenerateSeed` operation, is as follows:

        1. Let `seedMacKey` be a per-credential authenticator secret.

        1. Let `mac = LEFT(32, seedHandle)` and `seedHandleParams = DROP_LEFT(32, seedHandle)`.

        1. Verify that `mac == HMAC-SHA-256(seedMacKey, seedHandleParams || UTF8Encode("sign") || rpIdHash)`.
            If not, this `seedHandle` was generated by a different authenticator.
            Return CTAP2_ERR_X.

        1. Parse `[alg, up, uv, be] = seedHandleParams` as CBOR.

        1. Return `(alg, up, uv, be)`.

        `alg` MUST be a fully-specified COSEAlgorithmIdentifier with a single valid corresponding curve `crv`.
        Let `crv` be this curve.
        Let `crvOL` be the byte length of the order of the `crv` group.
        Let `crvSL` be the byte length of the scalar field of `crv`.

    1. TODO: NOT NEEDED? If `up` does not equal the `UP` flag value to be returned in the authenticator data, return CTAP2_ERR_X.
    1. TODO: NOT NEEDED WITH CREDPROTECT? If `uv` does not equal the `UV` flag value to be returned in the authenticator data, return CTAP2_ERR_X.

    1. Use `up`, `uv`, `be` and a per-credential authenticator secret
        as the seeds to deterministically regenerate the EC key pair `s, S` on the curve `crv`.

    1. Let `E` be the public key on the curve `crv` decoded from the uncompressed point `keyHandle.epk`
        as described in [SEC 1][sec1], section 2.3.4.
        If invalid, return CTAP2_ERR_X.

        ISSUE: Should `E` use COSE_Key format instead of SEC1?

    1. If `E` is the point at infinity, return CTAP2_ERR_X.

    1. Let `ikm = ECDH(s, E)`. Let `ikm_x` be the X coordinate of `ikm`,
        encoded as a byte string of length `crvSL` as described in [SEC 1][sec1], section 2.3.7.

    1. Let `credKey` be the `crvOL` bytes of output keying material
        from [HKDF-SHA-256][hkdf] with the arguments:

        - `salt`: Not set.
        - `IKM`: `ikm_x`.
        - `info`: The string `webauthn.sign.arkg.cred_key`, encoded as a UTF-8 byte string.
        - `L`: `crvOL`.

        Parse `credKey` as a big-endian unsigned number in the scalar field of `crv`.
        If `credKey` is greater than the order of the curve `crv`, return CTAP2_ERR_X.

    1. Let `macKey` be the 32 bytes of output keying material
        from [HKDF-SHA-256][hkdf] with the arguments:

        - `salt`: Not set.
        - `IKM`: `ikm_x`.
        - `info`: The string `webauthn.sign.arkg.mac_key`, encoded as a UTF-8 byte string.
        - `L`: 32.

    1. Verify that `keyHandle.mac == HMAC-SHA-256(macKey, seedHandle || keyHandle.epk || rpIdHash)`.
        If not, this `keyHandle` was generated for a different authenticator.
        Return CTAP2_ERR_X.

    1. Let `p = credKey + s` in the scalar field of `crv`.

    1. Return `p`.

    1. Let `sig` be a signature over `tbs` using private key `p` and algorithm `alg`.
        `sig` is DER encoded as described in [RFC 3279][rfc3279].

        ISSUE: Not always DER encoding for every `alg`?

    1. Return `{ sig: sig }` as the `sign` extension output and terminate these processing steps.


 1. If `genKey` is present:
    1. If the current operation is not an `authenticatorMakeCredential` operation,
        return CTAP2_ERR_X.

    1. (TODO: FOR KEM EXTENSION ONLY) Let `alg` be the authenticator's choice of one of the algorithms listed in `genKey.alg`.
        `alg` MUST be a fully-specified COSEAlgorithmIdentifier identifying a KEM scheme.
        If none is supported, return CTAP2_ERR_X.

    1. Use `up`, `uv`, `be` and a per-credential authenticator secret
        as the seeds to deterministically generate a new signing key pair with private key `p` and public key `P`.

    1. TODO: COMPUTE `up`, `uv`, `be`

    1. Let `P_enc` be `P` encoded in COSE_Key format.

    1. Let `ikm` be some random input key material.

    1. Let `keyHandle` be an authenticator-specific encoding of `ikm`, `alg`, `up`, `uv` and `be`,
        which the authenticator can later use to derive the same key pair `p, P`.
        The encoding SHOULD include integrity protection
        to ensure that a given `keyHandle` is valid for a particular authenticator.

        One possible implementation is as follows:

        1. Let `macKey` be a per-credential authenticator secret.

        1. Let `keyHandleParams = [alg, up, uv, be]` as CBOR.

        1. Let `keyHandle = HMAC-SHA-256(macKey, keyHandleParams || UTF8Encode("sign") || rpIdHash) || keyHandleParams`.

    1. Set the extension output `sign.pk` to `P_enc`. Set the extension output `sign.kh` to `keyHandle`.

        Note: Do not terminate extension processing, proceed with processing the steps below.


 1. If `sign` is present:
    1. If the current operation is not an `authenticatorGetAssertion` operation, return CTAP2_ERR_X.

    1. If `allowCredentials` is empty, return CTAP2_ERR_X.

    1. Let `credentialId` be the credential ID of the credential being used for this assertion.
        Let `keyHandle` be `sign.kh[credentialId]`.

    1. If `keyHandle` is null or undefined, return CTAP2_ERR_X.

    1. Decode the authenticator-specific encoding of `keyHandle`
        to extract the `alg`, `up`, `uv` and `be` values.
        This procedure SHOULD verify integrity to ensure that `keyHandle` was generated by this authenticator.

        One possible implementation,
        compatible with the example encoding described in the `genKey` operation,
        is as follows:

        1. Let `macKey` be a per-credential authenticator secret.

        1. Let `mac = LEFT(32, keyHandle)` and `keyHandleParams = DROP_LEFT(32, keyHandle)`.

        1. Verify that `mac == HMAC-SHA-256(macKey, keyHandleParams || UTF8Encode("sign") || rpIdHash)`.
            If not, this `keyHandle` was generated by a different authenticator.
            Return CTAP2_ERR_X.

        1. Parse `[alg, up, uv, be] = keyHandleParams` as CBOR.

        1. Return `(alg, up, uv, be)`.

        `alg` MUST be a fully-specified COSEAlgorithmIdentifier.

    1. TODO: NOT NEEDED? If `up` does not equal the `UP` flag value to be returned in the authenticator data, return CTAP2_ERR_X.
    1. TODO: NOT NEEDED? If `uv` does not equal the `UV` flag value to be returned in the authenticator data, return CTAP2_ERR_X.

    1. Use `up`, `uv`, `be` and a per-credential authenticator secret
        as the seeds to deterministically regenerate the signing key pair with private key `p` and public key `P`.
       TODO: Extra entropy here to support multiple keys at a time?

    1. Let `sig` be a signature over `tbs` using private key `p` and algorithm `alg`.

    1. Set the extension output `sign.sig` to `sig`. Return the extension output.


### Authenticator extension output

```cddl
$$extensionOutput //= (
    sign: signExtensionOutputs,
)

signExtensionOutputs = {
    spk: bstr,        ;   arkgGen outputs
    sh: bstr,
    //
    sig: bstr,        ; arkgSign or sign output
    //
    keys: [{          ; genKey outputs
      pk: bstr,       ; Public key
      kh: bstr,       ; Key handle
      att_sig?: bstr, ; Attestation signature over pk, kh, credProtect level, BE, BS, UP
                      ; (different signature construction than top-level attestation signature).
                      ; Trust path (x5c/etc) is the same as parent credential.
                      ; Each key has its own attestation signature.
                      ; TODO: Add getInfo to signal max number of keys at a time
                      ; TODO: Define signing and verification procedures

      okm?: bstr,     ; (kem extension only) Key encapsulation output
    }]
    //
}
```

- `spk`: The generated ARKG seed public key.
  Present only if the `arkgGen` input was set and the authenticator supports ARKG.

- `sh`: The seed handle of the generated ARKG seed public key.
  Present only if the `arkgGen` input was set and the authenticator supports ARKG.

- `keys`: The generated public keys.
  Present only if the `genKey` input was set and the `spk` output is absent.

  Each item in `keys` is a CBOR map with the following key-value pairs:

  - `pk`: The generated public key.

  - `kh`: The key handle of the generated public key.

  - `att_sig`: An attestation signature for `pk`.
    Present only if attestation was requested.

  - `okm`: (Valid only for the `kem` extension)
    The output of a key encapsulation between the public key given as the `kem.dec.pk` input
    and the secret key corresponding to the `pk` output.
    Present only if the `kem.dec.pk` input was present.

  If the `arkgSign` and `sign` inputs were both set,
  then the public key of this signature is determined by the `id` of the `PublicKeyCredential`:
  the signature is for the public key corresponding to `arkgSign.keyHandleByCredential[id]` if that exists,
  otherwise the signature is for the public key corresponding to `sign.keyHandleByCredential[id]`.

- `sig`: The signature. Present only if the `sign` or `arkgSign` input was set.


### RP operations

#### Generate ARKG seed

 1. Invoke `navigator.credentials.create()` or `navigator.credentials.get()`
    with the `sign` extension with a `arkgGenerateSeed` argument as defined above.

    Let `credentialId` be the credential ID of the returned credential.
    Let `seedPublicKey` and `seedHandle` be the respective outputs from the `sign` extension.

 1. Store `(credentialId, seedPublicKey, seedHandle)`
    as an ARKG seed for signing in the relevant user account.


#### Generate public key

 1. Let `(credentialId, seedPublicKey, seedHandle)`
    be one of the ARKG seeds stored in the relevant user account.

 1. Let `S = seedPublicKey`. Let `crv = seedPublicKey.crv`.
    Let `crvOL` be the byte length of the order of the `crv` group.
    Let `crvSL` be the byte length of the scalar field of `crv`.

 1. Generate an ephemeral EC key pair on the curve `crv`: `e, E`.
    If `E` is the point at infinity, start over from 1.

 1. Let `ikm = ECDH(e, S)`.
    Let `ikm_x` be the X coordinate of `ikm`,
    encoded as a byte string of length `crvSL` as described in [SEC 1][sec1], section 2.3.7.

 1. Destroy the ephemeral private key `e`.

 1. Let `credKey` be the `crvOL` bytes of output keying material
    from [HKDF-SHA-256][hkdf] with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.sign.arkg.cred_key`, encoded as a UTF-8 byte string.
    - `L`: `crvOL`.

    Parse `credKey` as a big-endian unsigned number in the scalar field of `crv`.
    If `credKey` is greater than the order of the curve `crv`, start over from 1.

 1. Let `macKey` be the 32 bytes of output keying material
    from [HKDF-SHA-256][hkdf] with the arguments:

    - `salt`: Not set.
    - `IKM`: `ikm_x`.
    - `info`: The string `webauthn.sign.arkg.mac_key`, encoded as a UTF-8 byte string.
    - `L`: 32.

 1. Let `P = (credKey * G) + S`,
    where * and + are elliptic curve scalar multiplication and point addition in the `crv` group
    and `G` is the group generator.

 1. If `P` is the point at infinity, start over from 1.

 1. Let `E_enc` be `E` encoded as described in [SEC 1][sec1], section 2.3.3,
    without point compression.

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

 1. Store `(credentialId, P, keyHandle)`
    as a public key for signing in the relevant user account.


## WebAuthn `kem` extension

TODO: Spell out the whole extension once details are settled.

TODO: What about encryption export laws etc? Not new to YubiKey, but new to FIDO.

Analogous to the `sign` extension,
but outputting the result of a Key Encapsulation Mechanism (KEM) -
for example, a Diffie-Hellman exchange - instead of a signature.
Inputs change like this:

```webidl
dictionary AuthenticationExtensionsKemInputs {
    AuthenticationExtensionsSignGenerateKeyInputs generateKey;
    AuthenticationExtensionsKemDecapsulateInputs decapsulate;

    AuthenticationExtensionsSignGenerateKeyInputs arkgGenerateSeed;
    AuthenticationExtensionsKemArkgDecapsulateInputs arkgDecapsulate;
}

dictionary AuthenticationExtensionsKemDecapsulateInputs {
    required BufferSource publicKey;
    record<USVString, BufferSource> keyHandleByCredential;
}

dictionary AuthenticationExtensionsKemArkgDecapsulateInputs {
    required BufferSource publicKey;
    required record<USVString, AuthenticationExtensionsSignArkgKeyHandle> keyHandleByCredential;
}
```

and outputs like this:

```webidl
partial dictionary AuthenticationExtensionsClientOutputs {
    AuthenticationExtensionsKemOutputs kem;
}

dictionary AuthenticationExtensionsKemOutputs {
    ArrayBuffer publicKey;
    ArrayBuffer keyHandle;

    ArrayBuffer seedPublicKey;
    ArrayBuffer seedHandle;

    ArrayBuffer okm;
}
```

```cddl
$$extensionOutput //= (
    kem: kemExtensionOutputs,
)

kemExtensionOutputs = {
    spk: bstr,    ; arkgGen outputs
    sh: bstr,
    //
    okm: bstr,    ; arkgDec or dec output
    //
    pk: bstr,     ; genKey outputs
    kh: bstr,
    ? okm: bstr,
}
```

and the last step of the `dec` and `arkgDec` authenticator operations is:

 1. Set the extension output `okm` to the result of an ECDH exhange between `p` and `[dh | arkgEcdh].publicKey`.

    ISSUE: Apply a KDF step to `okm` before returning from the authenticator?

    ISSUE: What is a suitable reference for a spec of an ECDH algorithm?

and the HKDF `info` arguments used in _derive ARKG private key_
are `webauthn.kem.arkg.cred_key` and `webauthn.kem.arkg.cred_key`.


RP operations are also the same,
except the ARKG seed and generated public keys are KEM keys instead of signing keys.


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
