(ns geheimnis.rsa
  "This namespace provides an RSA implementation."
  (:require [hasch.core :refer [edn-hash]]
            [geheimnis.base64 :as b64]
            #?(:cljs [cljs.reader :as r])))

(defrecord RSAKey [pub-key priv-key modulus])

#?(:clj
   (defmethod print-method geheimnis.rsa.RSAKey
     [{:keys [pub-key priv-key modulus]} ^java.io.Writer w]
     (.write w (str "#geheimnis/RSAKey " (pr-str {:pub-key
                                                  (b64/encode (.toByteArray pub-key))
                                                  :priv-key
                                                  (b64/encode (.toByteArray priv-key))
                                                  :modulus
                                                  (b64/encode (.toByteArray modulus))}))))
   :cljs
   (extend-type RSAKey
     IPrintWithWriter
     (-pr-writer [{:keys [pub-key priv-key modulus] :as this} writer _]
       (-write writer (str "#geheimnis/RSAKey "
                           (pr-str {:pub-key
                                    (b64/encode (.toByteArray pub-key))
                                    :priv-key
                                    (b64/encode (.toByteArray priv-key))
                                    :modulus
                                    (b64/encode (.toByteArray modulus))}))))))

(defn base64map->RSAKey [{:keys [pub-key priv-key modulus]}]
  (map->RSAKey {:pub-key (b64/base64->BigInt pub-key)
                :priv-key (when priv-key (b64/base64->BigInt priv-key))
                :modulus (b64/base64->BigInt modulus)}))

#?(:cljs
   (r/register-tag-parser! 'geheimnis/RSAKey base64map->RSAKey))


(defn gen-key
  "Generates a key of bit-size and returns a RSAKey. The RSAKey is
  printed and read for non-conflicting transmission with cljs (which
  has no native BigInteger type) and other BigInteger users in Base64,
  but the in memory representation is BigInteger."
  [bit-size & {:keys [random]}]
  #?(:clj
     (let [random (or random (java.security.SecureRandom.))
           one (BigInteger. "1")
           p (BigInteger/probablePrime (/ bit-size 2) random)
           q (BigInteger/probablePrime (/ bit-size 2) random)
           phi (.multiply (.subtract p one) (.subtract q one))

           modulus (.multiply p q)
           pub-key (BigInteger. "65537")
           priv-key (.modInverse pub-key phi)]
       (map->RSAKey {:pub-key pub-key
                     :priv-key priv-key
                     :modulus modulus}))
     :cljs
     ;; TODO we use the RSAGenerate method here, because
     ;; .probablePrime is not explicitly implemented. Check needed for
     ;; what is done there and implement it.
     (let [key (js/RSAKey.)
           pub-key (js/BigInteger. "65537")
           _ (.generate key bit-size "10001") ;; basis 16
           modulus (.-n key)
           priv-key (.-d key)]
       (map->RSAKey {:pub-key pub-key
                     :priv-key priv-key
                     :modulus modulus}))))



(defn encrypt
  "Encrypts BigInteger m provided the public key and modulus as Base64."
  [{:keys [pub-key modulus]} m]
  (.modPow m pub-key modulus))


(defn decrypt
  "Decrypts BigInteger e priveded the private key and modulus as Base64."
  [{:keys [priv-key modulus]} e]
  (.modPow e priv-key modulus))

(comment
  (require 'figwheel-sidecar.repl-api)
  (figwheel-sidecar.repl-api/cljs-repl)



  (def rsa-key #_(gen-key 10 :random (java.util.Random. 42))
    (gen-key 1024))

  (b64/encode (.toByteArray (:modulus rsa-key)))


  (BigInteger. (byte-array [1 0 0]))

  (js/BigInteger. (.toByteArray (js/BigInteger. "fffffffffffffffffffffffffffff" 16)))
  (.gcd (js/BigInteger. "123") (js/BigInteger. "3"))

  (def key (js/RSAKey.))

  (.generate key  1024 "65537")

  (.log js/console key)
  (.-d key)

  (js/BigInteger.  (js/Int8Array. (clj->js (edn-hash [1 2 3]))))

  (decrypt keys (read-string "#geheimnis/BigInt \"66363559570838882996297763680386052934789877756036437638538075638521703891529011150259410176893131814997266795104235685716433124547855929266295804896677760925819905684043513885974907570165006322147912346592186806119441475825845321015234893914149045729432226933836548398341740872760843160442790118643906855979\""))

  (decrypt rsa-key (encrypt rsa-key (js/BigInteger. "123")))

  (js/BigInteger. (clj->js (map #(if (> % 127) (- % 128) %)  (edn-hash [1 2 3]))))



  (.modPow (js/BigInteger. "12345") (js/BigInteger. "12345") (js/BigInteger. "123"))


  )
