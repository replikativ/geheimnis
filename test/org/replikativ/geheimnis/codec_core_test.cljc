(ns org.replikativ.geheimnis.codec-core-test
  "KAT + round-trip tests for geheimnis v2 codec + core. Byte values are compared
   via hex so the assertions are platform-neutral (JVM signed byte[] vs CLJS
   unsigned Uint8Array)."
  (:require #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing]])
            [org.replikativ.geheimnis.codec :as codec]
            [org.replikativ.geheimnis.core :as gc]))

(deftest base64url
  (testing "known vector — 'hello' is aGVsbG8 (unpadded url alphabet)"
    (is (= "aGVsbG8" (codec/bytes->b64url (codec/str->bytes "hello")))))
  (testing "decode is idempotent through encode"
    (is (= "SGVsbG8gd29ybGQ"
           (codec/bytes->b64url (codec/b64url->bytes "SGVsbG8gd29ybGQ")))))
  (testing "round-trip of 32 random bytes (via hex)"
    (let [b (gc/random-bytes 32)]
      (is (= (codec/bytes->hex b)
             (codec/bytes->hex (codec/b64url->bytes (codec/bytes->b64url b))))))))

(deftest hex
  (is (= "deadbeef" (codec/bytes->hex (codec/hex->bytes "deadbeef"))))
  (is (= "00ff10" (codec/bytes->hex (codec/hex->bytes "00ff10")))))

(deftest utf8
  (is (= "héllo ☃ 🔐" (codec/bytes->str (codec/str->bytes "héllo ☃ 🔐")))))

(deftest random-bytes-is-csprng-shaped
  (testing "requested length"
    (is (= 64 (count (codec/bytes->hex (gc/random-bytes 32))))))
  (testing "two draws differ (not a constant / Math.random-frozen source)"
    (is (not= (codec/bytes->hex (gc/random-bytes 16))
              (codec/bytes->hex (gc/random-bytes 16))))))

(deftest constant-time-equal
  (is (true?  (gc/ct-equal? (codec/hex->bytes "aabbcc") (codec/hex->bytes "aabbcc"))))
  (is (false? (gc/ct-equal? (codec/hex->bytes "aabbcc") (codec/hex->bytes "aabbcd"))))
  (testing "unequal length is not equal"
    (is (false? (gc/ct-equal? (codec/hex->bytes "aabb") (codec/hex->bytes "aabbcc"))))))
