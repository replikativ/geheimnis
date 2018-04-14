(ns geheimnis.core-test
  (:require [clojure.test :refer :all]
            [geheimnis.aes :as aes]
            [geheimnis.rsa :as rsa]
            [geheimnis.base64 :as b64]
            [geheimnis.md5 :as md5]))

(deftest aes-test
  (testing "AES tests."
    (is (= [7 7 7 7 7 7 7 7 7 7]
           (vec (aes/decrypt "foo" (aes/encrypt "foo" (byte-array (repeat 10 7)))))))
    (is (= (vec (aes/encrypt "foo" (byte-array (repeat 10 7))))
           [-70 -83 -75 9 -46 -97 70 -89 -124 80 -99 -15 109 -57 66 -108]))))


(deftest rsa-test
  (testing "RSA tests."
    (let [keys #geheimnis/RSAKey
          {:pub-key #geheimnis/Base64 "AQAB",
           :priv-key #geheimnis/Base64 "cGCnpCGlXIWxGG5qEKbM1AukV5CpvTFATg2xhHkVoxy9PO3e8hl1N4pxe0bBebh/f4xOJry7HqNr63N6SUqXJNJOHG1zqS2KoEMizr6pQBJMCgbc4tqqhV5koLph6jcAGq2dDYg+PNarU6ABzHRN2iRkHgqjwVT4joAJIUn+/eU=",
           :modulus #geheimnis/Base64 "AMojQfXnxSK1uSYHiRwlY8yZe7gPBGPvCQJ+if7236x9NaSN/Bt2FbCdkBzWVTQDzX70icNiUReTpUw5HwpJFvi0JzNgDDgtOdGyQ0Jd70HO44mu1Zo67XqoemiBlFCXrRFBx0wG/izQBChjrcm8p/ZZIj0DbK4fO+sJ5P2oFwiV"}]
      (is (= (rsa/decrypt keys (rsa/encrypt keys (BigInteger. "123")))
             (BigInteger. "123"))))
    (let [keys (rsa/gen-key 2048)]
      (is (= (rsa/decrypt keys (rsa/encrypt keys (BigInteger. "12345678910")))
             (BigInteger. "12345678910"))))))


(deftest base64-test
  (testing "Base64 encoding."
    (is (= (seq (b64/decode (b64/encode (byte-array (range 10)))))
           (range 10)))))

