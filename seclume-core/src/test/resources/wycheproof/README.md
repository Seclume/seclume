# Project Wycheproof test vectors

Copied unchanged from https://github.com/C2SP/wycheproof, directory `testvectors_v1`, at
commit `3fa63dd0344abb611f1fb1d77e119938603ea230` (2026-08-24). Licensed under the Apache
License, Version 2.0, the same as seclume; see the `NOTICE` file at the root of this repository.

`space.seclume.crypto.WycheproofTest` runs them. Only the primitives whose logic seclume owns
are here:

| File | What it checks in seclume |
| --- | --- |
| `aes_gcm_test.json` | `AesGcm` in Java for 128/192/256-bit keys, and `AesGcmCipher` (OpenSSL or CNG) |
| `hmac_sha{1,256,384,512}_test.json` | `Hmac` |
| `hkdf_sha{1,256,384,512}_test.json` | `Hkdf.extract` and `Hkdf.expand`, including the length limit |
| `pbkdf2_hmacsha{1,256,384,512}_test.json` | `Pbkdf2` |
| `ecdh_secp256r1_ecpoint_test.json` | `NativeP256`: peer points off the curve, on the twist, compressed or malformed |

To update: copy the newer files over these, change the commit above, run
`./mvnw -pl seclume-core test -Dtest=WycheproofTest`, and adjust the counts in
`WycheproofTest.coverage()` to what the new files contain.
