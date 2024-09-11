# DRAFT: WebAuthn `sign` and `kem` extensions

The authoritative up-to-date version of the `sign` extension is [WebAuthn PR #2078][webauthn-sign-pr].
See the [rendered preview](https://pr-preview.s3.amazonaws.com/w3c/webauthn/pull/2078.html#sctn-sign-extension) linked in the pull request.

_NOTE: This is a draft of a work in progress and **not implementation ready**.
All parts of this draft are subject to change._

Authors: Emil Lundberg (Yubico), John Bradley (Yubico)


## Introduction

These extensions enable Relying Parties to sign arbitrary data
and use key encapsulation mechanisms (KEM) using public key protocols
with private keys held by the WebAuthn authenticator.


## WebAuthn `sign` extension

Moved to [WebAuthn PR #2078][webauthn-sign-pr] as noted above.


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
[webauthn-sign-pr]: https://github.com/w3c/webauthn/pull/2078
