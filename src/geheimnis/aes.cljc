(ns geheimnis.aes
  "Namespace for symmetric AES encryption."
  (:require [hasch.core :refer [edn-hash]]
            #?@(:cljs [[goog.crypt.Aes]
                       [goog.crypt.Cbc]
                       [goog.crypt]
                       [goog.crypt.Pkcs7]]))

  #?(:clj (:import [javax.crypto Cipher]
                   [javax.crypto.spec SecretKeySpec]
                   [javax.crypto.spec IvParameterSpec])))


#?(:cljs (def byte-array clj->js))

(defn encrypt
  "Encrypts with AES/CBC/PKCS{5/7}Padding by hashing a 256 bit key out
  of key. Key can be any Clojure value, but should provide enough
  secret entropy!

  You can provide an alternate initial vector of unsigned(!) bytes of size 16 for CBC."
  [key m & {:keys [iv] :or {iv  [6 224 71 170 241 204 115 21 30 8 46 223 106 207 55 42]}}]
  #?(:clj
     (let [iv (IvParameterSpec. (byte-array (mapv #(if (> % 127) (- % 256) %) iv)))
           spec (SecretKeySpec. (byte-array (take 32 (edn-hash key))) "AES")
           cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
       (.init cipher Cipher/ENCRYPT_MODE spec iv)
       (.doFinal cipher m))
     :cljs (let [cipher (goog.crypt.Aes. (byte-array (take 32 (edn-hash key))))
                 cbc (goog.crypt.Cbc. cipher)
                 pkcs7 (goog.crypt.Pkcs7.)
                 padded (.encode pkcs7 16 m)]
             (.encrypt cbc padded (byte-array iv)))))


(defn decrypt
  "Decrypts with AES/CBC/PKCS{5/7}Padding by hashing a 256 bit key out of key.

  You can provide an alternate initial vector of unsigned(!) bytes of size 16 for CBC."
  [key e & {:keys [iv] :or {iv  [6 224 71 170 241 204 115 21 30 8 46 223 106 207 55 42]}}]
  #?(:clj
     (let [iv (IvParameterSpec. (byte-array (mapv #(if (> % 127) (- % 256) %) iv)))
           spec (SecretKeySpec. (byte-array (take 32 (edn-hash key))) "AES")
           cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
       (.init cipher Cipher/DECRYPT_MODE spec iv)
       (.doFinal cipher e))
     :cljs
     (let [cipher (goog.crypt.Aes. (byte-array (take 32 (edn-hash key))))
           cbc (goog.crypt.Cbc. cipher)
           pkcs7 (goog.crypt.Pkcs7.)]
       (.decode pkcs7 16 (.decrypt cbc e (byte-array iv))))))

(comment
  (decrypt "foo" (encrypt "foo" (byte-array (repeat 10 7))))

  (encrypt "foo" (byte-array (repeat 10 7)))

  (decrypt "foo" (byte-array (map #(if (neg? %) (+ % 256) %)
                                  [-70 -83 -75 9 -46 -97 70 -89 -124 80 -99 -15 109 -57 66 -108])))

  (vec (decrypt "foo" (byte-array (mapv #(if (> % 127) (- % 256) %)
                                        [6 224 71 170 241 204 115 21 30 8 46 223 106 207 55 42]))))


  ;; cljs
  (vec (decrypt "foo" (byte-array (mapv #(if (> % 127) (- % 256) %)
                                        [162 154 180 196 57 250 139 34 205 89 66 113 0 72 14 101]))))
  ;; clj
  (vec (encrypt "foo" (byte-array (repeat 16 7))))

  (decrypt "foo" (encrypt "foo" (clj->js (repeat 16 7))))

  (.log js/console (decrypt "foo" (encrypt "foo" (clj->js (repeat 16 7)))))

  (String. (decrypt "foo" (encrypt "foo" (.getBytes "barsssssssssssssssssssssssssssssssssss"
                                                    "UTF-8")))
           "UTF-8"))
