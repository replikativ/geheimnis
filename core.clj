#?(:clj (ns clj-crypto.core
          (:require [clojure.data.codec.base64 :as b64])
          (:import [java.security Key]
                   [java.security.interfaces RSAKey]
                   [java.security KeyPair]
                   [java.security KeyPairGenerator]
                   [javax.crypto Cipher]
                   [javax.crypto KeyGenerator]
                   [javax.crypto SecretKey]
                   [javax.crypto.spec SecretKeySpec]))


   (def key-pair-generator (KeyPairGenerator/getInstance  "RSA"))

   (.initialize key-pair-generator 1024)

   (def key-pair (.genKeyPair key-pair-generator))

   (spit "/tmp/priv.key" (String. (b64/encode (.getEncoded (.getPrivate key-pair))) "UTF-8"))


   (BigInteger. (byte-array (take 100 (repeatedly #(byte (- (rand-int 255) 128))))))

   (- (BigInteger. "abcd1234aaaaaaaaaaaaaaaaaaaaaaaaa" 16) 1)



   (vec (.getEncoded (.getPrivate key-pair)))

   (KeyPair. (.getPublic key-pair) (RSAKey. (b64/decode (.getBytes (slurp "/tmp/priv.key") "UTF-8"))))


   (def cipher (Cipher/getInstance "RSA/ECB/PKCS1Padding"))

   (.init cipher Cipher/ENCRYPT_MODE (.getPublic key-pair))



   (def challenge (byte-array (map byte (.toCharArray "plaintext"))
                              #_(take 100 (repeatedly #(byte (- (rand-int 255) 128))))))


   (def encrypted (.doFinal cipher challenge))

   (vec encrypted)




   (.init cipher Cipher/DECRYPT_MODE (.getPrivate key-pair))

   (def decrypted (.doFinal cipher encrypted))

   (= (vec decrypted) (vec challenge))

   (def public (.getPublic key-pair))


   (seq (.getEncoded public))


   (def private (.getPrivate key-pair))

   (seq (.getEncoded private))

   (spit "/tmp/test")
   )
