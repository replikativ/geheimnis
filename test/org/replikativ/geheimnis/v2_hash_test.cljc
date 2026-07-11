(ns org.replikativ.geheimnis.v2-hash-test
  "Known-answer tests for geheimnis v2 keyed hashing against published vectors:
   SHA-256 (NIST), HMAC-SHA-256 (RFC 4231), HKDF-SHA-256 (RFC 5869)."
  (:require #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            [org.replikativ.geheimnis.codec :as codec]
            [org.replikativ.geheimnis.hash :as h]))

(defn- hexh [bs] (codec/bytes->hex bs))

(deftest sha256-kat
  (testing "SHA-256(\"abc\") — NIST vector"
    (is (= "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
           (hexh (h/sha256 (codec/str->bytes "abc")))))))

(deftest hmac-sha256-kat
  (testing "RFC 4231 test case 2 (key \"Jefe\")"
    (is (= "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
           (hexh (h/hmac-sha256 (codec/str->bytes "Jefe")
                                (codec/str->bytes "what do ya want for nothing?")))))))

(deftest hkdf-sha256-kat
  (testing "RFC 5869 test case 1"
    (let [ikm  (codec/hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
          salt (codec/hex->bytes "000102030405060708090a0b0c")
          info (codec/hex->bytes "f0f1f2f3f4f5f6f7f8f9")
          okm  (h/hkdf ikm salt info 42)]
      (is (= 42 (codec/blen okm)))
      (is (= (str "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d5"
                  "6ecc4c5bf34007208d5b887185865")
             (hexh okm)))))
  (testing "empty salt / info still derives (extract uses zero salt)"
    (let [okm (h/hkdf (codec/str->bytes "input key material") nil nil 32)]
      (is (= 32 (codec/blen okm))))))
