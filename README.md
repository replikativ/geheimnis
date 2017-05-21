# geheimnis

Implementation of cross-platform (clj, cljs) cryptography. The library supports
AES/CBC/Pkcs7Padding with a 256 bit key and RSA with arbitrary keysize. If you
need something which is not provided, please open an issue. While `geheimnis` is
not supposed to cover all cryptographic options like OpenSSL compatibility with
a big set of chiffres, common and useful algorithms to do standard
public-private key solutions should be provided with a solid implementation.
`geheimnis` is supposed to be batteries included on Clojure level, so doing the
right thing should be easy.

This library is still very young, but encryption methods work between
platforms and are initialized with proper upstream/documented
parameters. If you hit any problems, open an issue.

## Usage <a href="https://gitter.im/replikativ/replikativ?utm_source=badge&amp;utm_medium=badge&amp;utm_campaign=pr-badge&amp;utm_content=badge"><img src="https://camo.githubusercontent.com/da2edb525cde1455a622c58c0effc3a90b9a181c/68747470733a2f2f6261646765732e6769747465722e696d2f4a6f696e253230436861742e737667" alt="Gitter" data-canonical-src="https://badges.gitter.im/Join%20Chat.svg" style="max-width:100%;"></a>

Add this to your leiningen project's dependencies:
[![Clojars Project](http://clojars.org/io.replikativ/geheimnis/latest-version.svg)](http://clojars.org/io.replikativ/geheimnis)


~~~clojure
(require '[geheimnis.rsa :refer [gen-key encrypt decrypt]]
         '[geheimnis.base64 :refer [encode decode]])

(def rsa-key (gen-key 1024))

(decrypt rsa-key (encrypt rsa-key (BigInteger. "123")))

(encode (:pub-key rsa-key)) ;; => #geheimnis/Base64 "AAECAwQFBgcICQ=="
~~~

~~~clojure
(require '[geheimnis.aes :refer [encrypt decrypt]])

(decrypt "s3cr3T" (encrypt "s3cr3T" (byte-array (range 10)))
~~~

## TODO
- include jsbn library with externs or as gclosure module
- the clj reader has problems compiling cljs with tagged literals
- use cljsjs/bignumber for RSA
- add padding support to RSA
- Explore http://nacl.cr.yp.to/ with https://download.libsodium.org/doc/ and https://www.npmjs.com/package/libsodium for proven safety


## License

Copyright © 2016-2017 Christian Weilbach

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
