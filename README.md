Just my workspace for designing JOSE things

## Overview

### JWS

JWS has:

- Header
- Payload (key is "payload", b64 encoded)
- Signature (key is "signature", b64 encoded)

Header is split into two parts: at least one must be present:

- Protected (key is "protected", b64 encoded)
- Unprotected (key is "header", raw text)

Signature is the output of HMAC signing protected header + payload.

Had a compact form (single signature, no unprotected header):

```text
b64url(protected header).b64url(payload).b64url(signature)
```

And a flat form

```json5
{
    "header": {"a": "abc"},
    "protected": "abc",
    "payload": "abc",
    "signature": "abc",
}
```

And a general form

```json5
{
    "payload": "abc",
    "signatures": [
        {
            "protected": "abc",
            "header": {"a": "abc"},
            "signature": "abc",
        }
    ]

}
```


### JWE



```rust
Jws<PayloadTy, Compact<ProtectedHeaderExtras>>;
Jws<PayloadTy, Flat<ProtectedHeaderExtras, UnProtectedHeaderExtras>>;
Jws<PayloadTy, General<ProtectedHeaderExtras, UnProtectedHeaderExtras>>;


enum JwsOptions<T> {
    Compact(Jws<T, Compact>),
    General(Jws<T, General>),
    Flat(Jws<T, Flat>),
}

struct Jws<PayloadTy, Format: JwsFormat=Compact<Empty>> {
    header: Format::Header,
    payload: PayloadTy,
    sig_data: Option<Format::SignatureData>
}

trait JwsFormat: Sealed {
    type Header;
}

struct Compact {}

```
