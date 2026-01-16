# geheimnis

[![Clojars Project](https://img.shields.io/clojars/v/org.replikativ/geheimnis.svg)](https://clojars.org/org.replikativ/geheimnis)
[![cljdoc badge](https://cljdoc.org/badge/org.replikativ/geheimnis)](https://cljdoc.org/d/org.replikativ/geheimnis/CURRENT)

Implementation of cross-platform (clj, cljs) cryptography. The library supports
AES/CBC/Pkcs7Padding with a 256 bit key and RSA with arbitrary keysize, as well as simple MD5 hashing. If you
need something which is not provided, please open an issue. While `geheimnis` is
not supposed to cover all cryptographic options like OpenSSL compatibility with
a big set of chiffres, common and useful algorithms to do standard
public-private key solutions should be provided with a solid implementation.
`geheimnis` is supposed to be batteries included on Clojure level, so doing the
right thing should be easy.

This library is still very young, but encryption methods work between
platforms and are initialized with proper upstream/documented
parameters. If you hit any problems, open an issue.

## Usage

Add this to your project dependencies:

**deps.edn:**
```clojure
org.replikativ/geheimnis {:mvn/version "0.1.15"}
```

**Leiningen/Boot:**
```clojure
[org.replikativ/geheimnis "0.1.15"]
```

### RSA Example

```clojure
(require '[org.replikativ.geheimnis.rsa :refer [gen-key encrypt decrypt]]
         '[org.replikativ.geheimnis.base64 :refer [encode decode]])

(def rsa-key (gen-key 1024))

(decrypt rsa-key (encrypt rsa-key (BigInteger. "123")))

(encode (:pub-key rsa-key)) ;; => #geheimnis/Base64 "AAECAwQFBgcICQ=="
```

### AES Example

```clojure
(require '[org.replikativ.geheimnis.aes :refer [encrypt decrypt]])

(decrypt "s3cr3T" (encrypt "s3cr3T" (byte-array (range 10))))
```

### MD5 Example

```clojure
(require '[org.replikativ.geheimnis.md5 :refer [encode]])

(encode "geheimnis") ;; => "525e92c6aa11544a2ab794f8921ecb0f"
```

## Development

**Run tests:**
```bash
clojure -M:test
```

**Format code:**
```bash
clojure -M:format      # Check formatting
clojure -M:ffix        # Auto-fix formatting
```

**Build JAR:**
```bash
clojure -T:build jar
```

**Install locally:**
```bash
clojure -T:build install
```

## Changes from io.replikativ to org.replikativ

This library has been migrated from `io.replikativ/geheimnis` to `org.replikativ/geheimnis`.

**Namespace changes:**
- `geheimnis.*` → `org.replikativ.geheimnis.*`

**Old (deprecated):**
```clojure
(require '[geheimnis.rsa :refer [gen-key]])
```

**New:**
```clojure
(require '[org.replikativ.geheimnis.rsa :refer [gen-key]])
```

## TODO
- include jsbn library with externs or as gclosure module
- the clj reader has problems compiling cljs with tagged literals
- use cljsjs/bignumber for RSA
- add padding support to RSA
- Explore http://nacl.cr.yp.to/ with https://download.libsodium.org/doc/ and https://www.npmjs.com/package/libsodium for proven safety

## License

Copyright © 2016-2025 Christian Weilbach, Konrad Kühne

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
