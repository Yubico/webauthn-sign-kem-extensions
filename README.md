# DRAFT: WebAuthn `sign` and `kem` extensions

_NOTE: This is a draft of a work in progress and **not implementation ready**.
All parts of this draft are subject to change._

Authors: Emil Lundberg (Yubico), John Bradley (Yubico)


## Introduction

These extensions enable Relying Parties to sign arbitrary data
and use key encapsulation mechanisms (KEM) using public key protocols
with private keys held by the WebAuthn authenticator.


### Attestation considerations

Because the requested number of keys might be too large to fit in client-to-authenticator protocol messages,
one key generation request at the WebAuthn layer might need to be implemented via a batch of multiple authenticator operations.
This also means that the authenticator extension outputs at the WebAuthn layer
might not include all of the public keys returned in the client extension outputs.
For these reasons the generated public keys are conveyed primarily via client extension outputs,
and when the RP requests attestation, a unique attestation signature is generated for each generated public key.
These attestation signatures are distinct from the top-level attestation statement,
and sign of over different signed data.


### Considerations for discoverable keys

Although this extension may be used with discoverable keys,
it does not support usage with an empty `allowCredentials`
because the intended use is for signing data that is meaningful on its own.
This is unlike a random authentication challenge, which may be meaningless on its own
and is used only to guarantee that an authentication signature was generated recently.
In order to sign meaningful data, the RP must first know what is to be signed,
and thus presumably must also first know which key is to be used for signing.
Thus, the signing use case is largely incompatible with the anonymous authentication challenge use case.
Therefore the restriction to non-empty `allowCredentials`
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


### Extension identifier

`sign`


### Operation applicability

Registration and authentication


### Client extension input

```webidl
partial dictionary AuthenticationExtensionsClientInputs {
    AuthenticationExtensionsSignInputs sign;
}

dictionary AuthenticationExtensionsSignInputs {
    AuthenticationExtensionsSignGenerateKeyInputs generateKey;
    AuthenticationExtensionsSignSignInputs sign;
}
```

- `generateKey`

  Inputs for generating signing public keys, and optionally generating a signature with each key pair.
  Valid only during a registration ceremony.

- `sign`

  Inputs for generating a signature.
  Valid only during an authentication ceremony.

```
dictionary AuthenticationExtensionsSignGenerateKeyInputs {
    required sequence<AuthenticationExtensionsSignGenerateKeyAlgorithmsEntry> algorithms;
    unsigned long numKeys = 1;
    BufferSource tbs;
}
```

- `algorithms`: A list of signature algorithm options to choose from,
  ordered from most preferred to least preferred.
  The client and authenticator make a best-effort to choose the most preferred algorithm possible.
  If none of the listed algorithms is available, the operation fails.

  This member MUST NOT be empty.

- `tbs`: Optional data to be signed.
  If present, it will be signed by each generated key pair.

```
dictionary AuthenticationExtensionsSignGenerateKeyAlgorithmsEntry {
    required COSEAlgorithmIdentifier alg;
    unsigned long numKeys = 1;
}
```

- `alg`: The cryptographic signature algorithm with which the newly generated credential will be used,
  and thus also the type of key pair to be generated.

- `numKeys`: The number of key pairs to generate if this algorithm is chosen.

```
dictionary AuthenticationExtensionsSignSignInputs {
    required BufferSource tbs;
    required record<USVString, AuthenticationExtensionsSignKeyHandle> keyHandleByCredential;
}
```

Inputs for generating a signature with a previously generated key pair.

- `tbs`: The data to be signed. Its format may depend on the signature algorithm.

- `keyHandleByCredential`: A record mapping base64url encoded credential IDs
  to signing key handles to use for each credential.

```
dictionary AuthenticationExtensionsSignKeyHandle {
    required BufferSource kid;
    BufferSource args;
}
```

TODO: Generalize this as a new COSE/JOSE data type (e.g., `COSEKeyReference`)?

A reference to a previously generated key pair, with optional additional arguments to use during signing.

- `kid`: An opaque byte string referencing a previously generated key pair.
    This is returned as the `kid` member of the `generatedKeys` client extension output when the key pair was generated.

- `args`: Optional, algorithm-specific additional arguments to use during signing.
    The internal format is specified by the signature algorithm.


### Client extension processing

 1. If none of `generateKey` or `sign` is present,
    return a "NotSupportedError" DOMException.

 1. If `generateKey` is present:

    1. If the current ceremony is not a registration ceremony,
        return a DOMException whose name is "NotSupportedError".

    1. Set the `sign` authenticator extension input to a CBOR map with the entries:
        - `alg`: A CBOR array containing the value of the `alg` member of each item of `generateKey.algorithms`, in order.
        - `num`: A CBOR map constructed as follows:

            Let `num` be a new CBOR map.
            For each item of `generateKey.algorithms`:

              If `numKeys` is not 1, set `num[alg]` to `numKeys`.

        - `tbs`: `generateKey.tbs` encoded as a CBOR byte string.

    1. After successfully _invoking the authenticatorMakeCredential operation_,
        run the following:

        1. Let `generatedCredentials` be an empty list.

        1. Using the _credentialCreationData_ constructed in the success branch of Step 21 of [[Create]]():

            1. Let `chosenNumKeys` be the value of the `numKeys` member of the item of `generateKey.algorithms`
                whose `alg` member equals `credentialCreationData.attestationObjectResult.authData.extensions.sign.pk.alg`.

            1. Let `generatedCredential` be a new map with the entries:

                - `attestationObject`: `credentialCreationData.attestationObjectResult`.
                - `clientDataJSON`: `credentialCreationData.clientDataJSONResult`.
                - `publicKey`: The value of `credentialCreationData.attestationObjectResult.authData.extensions.sign.pk`.
                - `kid`: The value of `credentialCreationData.attestationObjectResult.authData.extensions.sign.kid`.
                - `signature`: The value of `credentialCreationData.attestationObjectResult.authData.extensions.sign.sig` if present, otherwise omitted.

                Append `generatedCredential` to `generatedCredentials`.

            1. While `generatedCredentials` has length less than `chosenNumKeys`:

                1. If `chosenNumKeys` is unreasonably high as determined at the client's discretion, [=break=].

                1. _Invoke the authenticatorMakeCredential operation_ again
                    on the [=selected authenticator=] with the same inputs.

                    _TODO: Need to introduce some new CTAP2 pinUvAuthToken permission to reuse UP & UV state for multiple makeCredential operations?_

                1. Let `attestationObjectResult` be the bytes returned from the successful _authenticatorMakeCredential_ operation.
                    If the _authenticatorMakeCredential_ operation fails, [=break=].

                1. Let `generatedCredential` be a new map with the entries:

                    - `attestationObject`: `attestationObjectResult`.
                    - `clientDataJSON`: `credentialCreationData.clientDataJSONResult`.
                    - `publicKey`: The value of `attestationObjectResult.authData.extensions.sign.pk`.
                    - `kid`: The value of `attestationObjectResult.authData.extensions.sign.kid`.
                    - `signature`: The value of `attestationObjectResult.authData.extensions.sign.sig` if present, otherwise omitted.

                    Append `generatedCredential` to `generatedCredentials`.

        1. Set the `sign` client extension output to a new map with the entries:

            - `generatedKeys`: `generatedKeys`.

 1. If `sign` is present:

    1. If the current ceremony is not an authentication ceremony,
        return a DOMException whose name is "NotSupportedError".

    1. If `sign.keyHandleByCredential` is empty,
        return a DOMException whose name is "NotSupportedError".

    1. If any key in `sign.keyHandleByCredential` is the empty string,
        or is not a valid base64url encoding,
        or does not equal the id of some element of `allowCredentials`
        after performing base64url decoding,
        return a DOMException whose name is "SyntaxError".

    1. Let `keyHandleKids` and `keyHandleArgs` be CBOR arrays constructed as follows:

        1. For each `credentialId` in `allowCredentials`:

            1. Let `encodedCredentialId` be the base64url encoding of `credentialId`.
            1. Let `keyHandle` be `sign.keyHandleByCredential[encodedCredentialId]`.
            1. Append `keyHandle.kid`, encoded as a CBOR byte string, to `keyHandleKids`.
            1. If `keyHandle.args` is present, append `keyHandle.args`, encoded as a CBOR byte string, to `keyHandleArgs`.
                Otherwise, append a CBOR null value (major type 7, value 22) to `keyHandleArgs`.

        NOTE: If the client divides `allowCredentials` into smaller batches to fit authenticator message length limits,
        the client MUST also divide `keyHandleKids` and `keyHandleArgs` into batches of the same size and in the same order.

    1. Set the `sign` authenticator extension input to a CBOR map with the entries:
        - `kid`: `keyHandleKids`.
        - `tbs`: `sign.tbs` encoded as a CBOR byte string.
        - `args`: `keyHandleArgs`, if at least one element of `keyHandleArgs` is not null. Otherwise omit the `args` entry.

    1. After successfully _invoking the authenticatorGetAssertion operation_,
        set the `sign` client extension output to a new map with the entries:

        - `signature`: A copy of the `sign.sig` authenticator extension output.


### Client extension output

```webidl
partial dictionary AuthenticationExtensionsClientOutputs {
    AuthenticationExtensionsSignOutputs sign;
}
```

```webidl
dictionary AuthenticationExtensionsSignOutputs {
    sequence<AuthenticationExtensionsSignGenerateKeyOutputs> generatedKeys;
    ArrayBuffer                                              signature;
}
```

- `generatedKeys`: The generated public keys.
  The length of this sequence is at least 1 and at most equal to the `generateKey.numKeys` extension input.
  Present only and always during registration ceremonies.

- `signature`: The signature over the input data.
  Present only and always during authentication ceremonies.

```webidl
dictionary AuthenticationExtensionsSignGenerateKeyOutputs {
    required ArrayBuffer attestationObject;
    required ArrayBuffer clientDataJSON;

    required ArrayBuffer publicKey;
    required ArrayBuffer kid;
    ArrayBuffer signature;
}
```

- `attestationObject`: An attestation object containing the generated public key in the `sign` authenticator extension output.
  Note that the user credential conveyed by this attestation object may not be the same
  as the credential conveying this client extension output.

- `clientDataJSON`: The JSON-compatible serialization of the client data used to sign `attestationObject`.

- `publicKey`: A copy of the `sign.pk` authenticator extension output in the authenticator data in `attestationObject`.
  This is provided for convenience for RPs that do not need attestation.

- `kid`: A copy of the `sign.kid` authenticator extension output in the authenticator data in `attestationObject`.
  This is provided for convenience for RPs that do not need attestation.

- `signature`: A copy of the `sign.sig` authenticator extension output in the authenticator data in `attestationObject`.
  This is provided for convenience for RPs that do not need attestation.


### Authenticator extension input

**`sign` extension**:

```cddl
$$extensionInput //= (
  sign: {
    ; Registration (key generation) input
    alg: [ + alg: int .within COSEAlgorithmIdentifier],
    num: { * int .within COSEAlgorithmIdentifier => uint .ne 1 },
    ? tbs: bstr,
    //
    ; Authentication (signing) input
    kid: [ + bstr ],
    tbs: bstr,
    ? args: [ + bstr / null ],
  },
)
```


### Authenticator processing steps

 1. Let `UP`, `UV` and `BE` represent the values that will be returned for the respective authenticator data flags.

 1. If the current operation is an `authenticatorMakeCredential` operation:

    1. Let `auxIkm` denote some, possibly empty, random entropy and/or auxiliary data to be used to generate a signing key pair.

    1. Use `UP`, `UV`, `BE`, `auxIkm` and a per-credential authenticator secret
        as the seeds to deterministically generate a new signing key pair with private key `p` and public key `P`.
        `p, P` MUST use the same signature algorithm as the parent credential being created.

    1. Let `kid` be an authenticator-specific encoding of `UP`, `UV`, `BE` and `auxIkm`,
        which the authenticator can later use to re-generate the same key pair `p, P`.
        The encoding SHOULD include integrity protection
        to ensure that a given `kid` is valid for a particular authenticator.

        One possible implementation is as follows:

        1. Let `macKey` be a per-credential authenticator secret.

        1. Let `kidParams = [UP, UV, BE, auxIkm]` as CBOR.

        1. Let `kid = HMAC-SHA-256(macKey, kidParams || UTF8Encode("sign") || rpIdHash) || kidParams`.

    1. Let `P_enc` be `P` encoded in COSE_Key format.

    1. Set the extension output `sign.pk` to `P_enc`. Set the extension output `sign.kid` to `kid`.

    1. If `tbs` is present, set the extension output `sign.sig` to the result of signing `tbs` using private key `p`.
        The output signature format is determined by the signature algorithm of `p`.
        Terminate these extension processing steps.

 1. If the current operation is an `authenticatorGetAssertion` operation:
    1. If `allowCredentials` is empty, return CTAP2_ERR_X.

    1. If `tbs` is not present or `kid` is not present,
        or if the length of `kid` does not equal the length of `allowCredentials`,
        return CTAP2_ERR_X.

    1. If `sign.args` is present and the length of `sign.args` does not equal the length of `allowCredentials`,
        return CTAP2_ERR_X.

    1. Let `credentialId` be the credential ID of the credential being used for this assertion.
        Let `credentialIdIndex` be the index of `credentialId` in `allowCredentials`.
        Let `kid` be `sign.kid[credentialIdIndex]`.
        Let `args` be `sign.args[credentialIdIndex]` if `sign.args` is present, otherwise let `args` be null.

    1. If `kid` is null or undefined, return CTAP2_ERR_X.

    1. Decode the authenticator-specific encoding of `kid` and re-generate the key pair `p, P`.

        This procedure SHOULD verify integrity to ensure that `kid` was generated by this authenticator.

        One possible implementation,
        compatible with the example encoding described above for `authenticatorMakeCredential` opersions,
        is as follows:

        1. Let `macKey` be a per-credential authenticator secret.

        1. Let `mac = LEFT(32, kid)` and `kidParams = DROP_LEFT(32, kid)`.

        1. Verify that `mac == HMAC-SHA-256(macKey, kidParams || UTF8Encode("sign") || rpIdHash)`.
            If not, this `kid` was generated by a different authenticator.
            Return CTAP2_ERR_X.

        1. Parse `[createUP, createUV, createBE, auxIkm] = kidParams` as CBOR.

        1. Return `(createUP, createUV, createBE, auxIkm)`.

    1. If `createUP` does not equal `UP`, return CTAP2_ERR_X.
    1. If `createUV` does not equal `UV`, return CTAP2_ERR_X.
    1. If `createBE` does not equal `BE`, return CTAP2_ERR_X.

    1. Use `UP`, `UV`, `BE`, `auxIkm` and a per-credential authenticator secret
        as the seeds to deterministically generate a new signing key pair with private key `p` and public key `P`.
        `p, P` MUST use the same signature algorithm as the parent credential being asserted.

    1. Set the extension output `sign.sig` to the result of signing `tbs` using private key `p`
        and  optional additional arguments `args`.
        The output signature format is determined by the signature algorithm of `p`.


### Authenticator extension output

```cddl
$$extensionOutput //= (
  sign: {
    ; Registration (key generation) outputs
    pk: bstr,     ; Generated signing public key
    kid: bstr,    ; Opaque identifier for the key pair
    ? sig: bstr,  ; Signature over tbs input (if requested)
    //
    ; Authentication (signing) outputs
    sig: bstr,    ; Signature over tbs input
  },
)
```

- `pk`: The generated public key.
  Present only in `authenticatorMakeCredential` operations.

- `kid`: The key handle of the generated public key.
  Present only in `authenticatorMakeCredential` operations.

- `sig`: A signature over the `sign` extension input `tbs`, verifiable with public key `pk`.
  Always present in `authenticatorGetAssertion` operations.
  Present in `authenticatorMakeCredential` operations only if the `tbs` input was present.


## WebAuthn `kem` extension

TODO: Spell out the whole extension once details are settled.

TODO: What about encryption export laws etc? Not new to YubiKey, but new to FIDO.

Analogous to the `sign` extension,
but outputting the result of a Key Encapsulation Mechanism (KEM) -
for example, a Diffie-Hellman exchange - instead of a signature.

Instead of the input `tbs: BufferSource` there's an input `publicKey: COSEKey` with the decapsulation public key,
and instead of the output `signature: BufferSource` there's an output `okm: BufferSource` containing the decapsulation result.

ISSUE: Apply a KDF step to `okm` before returning from the authenticator?


[att-cred-data]: https://w3c.github.io/webauthn/#attested-credential-data
[authdata]: https://w3c.github.io/webauthn/#authenticator-data
[ctap2-canon]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
[hkdf]: https://tools.ietf.org/html/rfc5869
[privacy-cons]: https://www.w3.org/TR/2019/WD-webauthn-2-20191126/#sctn-credential-id-privacy-leak
[rfc3279]: https://tools.ietf.org/html/rfc3279.html
[rp-auth-ext-processing]: https://w3c.github.io/webauthn/#sctn-verifying-assertion
[rp-reg-ext-processing]: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
[sec1]: http://www.secg.org/sec1-v2.pdf
