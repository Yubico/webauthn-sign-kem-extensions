# DRAFT: WebAuthn `sign` extension

_NOTE: This is a draft of a work in progress and **not implementation ready**.
All parts of this draft are subject to change._

Authors: Emil Lundberg (Yubico), John Bradley (Yubico)


## Introduction

This extension enables Relying Parties to sign arbitrary data using public key signature algorithms.


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

  Inputs for generating signing public keys, and optionally generating a signature with each key.
  Valid only during a registration ceremony.

- `sign`

  Inputs for generating a signature.
  Valid only during an authentication ceremony.

```
dictionary AuthenticationExtensionsSignGenerateKeyInputs {
    unsigned long numKeys = 1;
    BufferSource tbs;
}
```

- `numKeys`: The number of key pairs to generate.

- `tbs`: Optional data to be signed.
  If present, it will be signed by each generated key.

```
dictionary AuthenticationExtensionsSignSignInputs {
    required BufferSource tbs;
    required record<USVString, BufferSource> keyHandleByCredential;
}
```

Inputs for generating a signature with a previously generated public key.

- `tbs`: The data to be signed. Its format may depend on the signature algorithm.

- `keyHandleByCredential`: A record mapping base64url encoded credential IDs
  to signing key handles to use for each credential.


### Client extension processing

 1. If none of `generateKey` or `sign` is present,
    return a "NotSupportedError" DOMException.

 1. If `generateKey` is present:

    1. If the current ceremony is not a registration ceremony,
        return a DOMException whose name is "NotSupportedError".

    1. Set the `sign` authenticator extension input to a CBOR map with the entries:
        - `tbs`: `generateKey.tbs` encoded as a CBOR byte string.

    1. After successfully _invoking the authenticatorMakeCredential operation_,
        run the following:

        1. Let `generatedCredentials` be an empty list.

        1. Using the _credentialCreationData_ constructed in the success branch of Step 21 of [[Create]]():

            1. Let `generatedCredential` be a new map with the entries:

                - `attestationObject`: `credentialCreationData.attestationObjectResult`.
                - `clientDataJSON`: `credentialCreationData.clientDataJSONResult`.
                - `publicKey`: The value of `credentialCreationData.attestationObjectResult.authData.extensions.sign.pk`.
                - `kh`: The value of `credentialCreationData.attestationObjectResult.authData.extensions.sign.kh`.
                - `sig`: The value of `credentialCreationData.attestationObjectResult.authData.extensions.sign.sig` if present, otherwise omitted.

                Append `generatedCredential` to `generatedCredentials`.

            1. While `generatedCredentials` has length less than `generateKey.numKeys`:

                1. If `generateKey.numKeys` is unreasonably high as determined at the client's discretion, [=break=].

                1. _Invoke the authenticatorMakeCredential operation_ again
                    on the [=selected authenticator=] with the same inputs.

                    _TODO: Need to introduce some new CTAP2 pinUvAuthToken permission to reuse UP & UV state for multiple makeCredential operations?_

                1. Let `attestationObjectResult` be the bytes returned from the successful _authenticatorMakeCredential_ operation.
                    If the _authenticatorMakeCredential_ operation fails, [=break=].

                1. Let `generatedCredential` be a new map with the entries:

                    - `attestationObject`: `attestationObjectResult`.
                    - `clientDataJSON`: `credentialCreationData.clientDataJSONResult`.
                    - `publicKey`: The value of `attestationObjectResult.authData.extensions.sign.pk`.
                    - `kh`: The value of `attestationObjectResult.authData.extensions.sign.kh`.
                    - `sig`: The value of `attestationObjectResult.authData.extensions.sign.sig` if present, otherwise omitted.

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

    1. Set the `sign` authenticator extension input to a CBOR map with the entries:
        - `tbs`: `sign.tbs` encoded as a CBOR byte string.
        - `kh`: a CBOR map mapping the base64url decoding of each key of `sign.keyHandleByCredential`
          to its corresponding value.

        NOTE: If/when batching `allowCredentials` values to fit authenticator message length limits,
        the client MUST also reduce `kh` in the same way so it only includes keys (whose base64url encoding is) present in `allowCredentials`.

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
    required ArrayBuffer keyHandle;
    ArrayBuffer signature;
}
```

- `attestationObject`: An attestation object containing the generated key in the `sign` authenticator extension output.
  Note that the user credential conveyed by this attestation object may not be the same
  as the credential conveying this client extension output.

- `clientDataJSON`: The JSON-compatible serialization of the client data used to sign `attestationObject`.

- `publicKey`: A copy of the `sign.pk` authenticator extension output in the authenticator data in `attestationObject`.
  This is provided for convenience for RPs that do not need attestation.

- `keyHandle`: A copy of the `sign.kh` authenticator extension output in the authenticator data in `attestationObject`.
  This is provided for convenience for RPs that do not need attestation.

- `signature`: A copy of the `sign.sig` authenticator extension output in the authenticator data in `attestationObject`.
  This is provided for convenience for RPs that do not need attestation.


### Authenticator extension input

**`sign` extension**:

```cddl
$$extensionInput //= (
  sign: {
    ? tbs: bstr,             ; Registration (key generation) input
    //
    kh: { + bstr => bstr },  ; Authentication (signing) input
    tbs: bstr,
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

    1. Let `keyHandle` be an authenticator-specific encoding of `UP`, `UV`, `BE` and `auxIkm`,
        which the authenticator can later use to re-generate the same key pair `p, P`.
        The encoding SHOULD include integrity protection
        to ensure that a given `keyHandle` is valid for a particular authenticator.

        One possible implementation is as follows:

        1. Let `macKey` be a per-credential authenticator secret.

        1. Let `keyHandleParams = [UP, UV, BE, auxIkm]` as CBOR.

        1. Let `keyHandle = HMAC-SHA-256(macKey, keyHandleParams || UTF8Encode("sign") || rpIdHash) || keyHandleParams`.

    1. Let `P_enc` be `P` encoded in COSE_Key format.

    1. Set the extension output `sign.pk` to `P_enc`. Set the extension output `sign.kh` to `keyHandle`.

    1. If `tbs` is present, set the extension output `sign.sig` to the result of signing `tbs` using private key `p`.
        The output signature format is determined by the signature algorithm of `p`.
        Terminate these extension processing steps.

 1. If the current operation is an `authenticatorGetAssertion` operation:
    1. If `tbs` is not present or `kh` is not present,
        return CTAP2_ERR_X.

    1. If `allowCredentials` is empty, return CTAP2_ERR_X.

    1. Let `credentialId` be the credential ID of the credential being used for this assertion.
        Let `keyHandle` be `sign.kh[credentialId]`.

    1. If `keyHandle` is null or undefined, return CTAP2_ERR_X.

    1. Decode the authenticator-specific encoding of `keyHandle` and re-generate the key pair `p, P`.
       to extract the `createUP`, `createUV`, `createBE` and `auxIkm` values.

        This procedure SHOULD verify integrity to ensure that `keyHandle` was generated by this authenticator.

        One possible implementation,
        compatible with the example encoding described above for `authenticatorMakeCredential` opersions,
        is as follows:

        1. Let `macKey` be a per-credential authenticator secret.

        1. Let `mac = LEFT(32, keyHandle)` and `keyHandleParams = DROP_LEFT(32, keyHandle)`.

        1. Verify that `mac == HMAC-SHA-256(macKey, keyHandleParams || UTF8Encode("sign") || rpIdHash)`.
            If not, this `keyHandle` was generated by a different authenticator.
            Return CTAP2_ERR_X.

        1. Parse `[createUP, createUV, createBE, auxIkm] = keyHandleParams` as CBOR.

        1. Return `(createUP, createUV, createBE, auxIkm)`.

    1. If `createUP` does not equal `UP`, return CTAP2_ERR_X.
    1. If `createUV` does not equal `UV`, return CTAP2_ERR_X.
    1. If `createBE` does not equal `BE`, return CTAP2_ERR_X.

    1. Use `UP`, `UV`, `BE`, `auxIkm` and a per-credential authenticator secret
        as the seeds to deterministically generate a new signing key pair with private key `p` and public key `P`.
        `p, P` MUST use the same signature algorithm as the parent credential being asserted.

    1. Set the extension output `sign.sig` to the result of signing `tbs` using private key `p`.
        The output signature format is determined by the signature algorithm of `p`.


### Authenticator extension output

```cddl
$$extensionOutput //= (
  sign: {
    ; Registration (key generation) outputs
    pk: bstr,     ; Generated signing public key
    kh: bstr,     ; Key handle for public key
    ? sig: bstr,  ; Signature over tbs input (if requested)
    //
    ; Authentication (signing) outputs
    sig: bstr,    ; Signature over tbs input
  },
)
```

- `pk`: The generated public key.
  Present only in `authenticatorMakeCredential` operations.

- `kh`: The key handle of the generated public key.
  Present only in `authenticatorMakeCredential` operations.

- `sig`: A signature over the `sign` extension input `tbs`, verifiable with public key `pk`.
  Always present in `authenticatorGetAssertion` operations.
  Present in `authenticatorMakeCredential` operations only if the `tbs` input was present.


[att-cred-data]: https://w3c.github.io/webauthn/#attested-credential-data
[authdata]: https://w3c.github.io/webauthn/#authenticator-data
[ctap2-canon]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form
[hkdf]: https://tools.ietf.org/html/rfc5869
[privacy-cons]: https://www.w3.org/TR/2019/WD-webauthn-2-20191126/#sctn-credential-id-privacy-leak
[rfc3279]: https://tools.ietf.org/html/rfc3279.html
[rp-auth-ext-processing]: https://w3c.github.io/webauthn/#sctn-verifying-assertion
[rp-reg-ext-processing]: https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
[sec1]: http://www.secg.org/sec1-v2.pdf
