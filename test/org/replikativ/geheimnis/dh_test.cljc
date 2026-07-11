(ns org.replikativ.geheimnis.dh-test
  "X25519 key agreement round-trip + a fixed interop KAT. The two keypairs and
   their shared secret were produced on the JVM; a CLJS/Node peer that derives
   the SAME secret from either half is byte-compatible — two peers on different
   platforms agree a key with no pre-shared secret. Both use their native X25519
   (java.security / Web Crypto), so agreement here is a real correctness anchor."
  (:require #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing async]])
            [clojure.core.async :as a]
            [org.replikativ.geheimnis.dh :as dh]
            [org.replikativ.geheimnis.codec :as codec]))

(def ^:private a-priv  "f30161b780294aa43a007352eec5f750ada316be85928b32e5b2a7cf0aa9f369")
(def ^:private a-pub   "5e8bba745fb55760deff40ecc4832d72859599b463a2a033a9e17f18bda0e643")
(def ^:private b-priv  "ced519ca9f4bec17448e42de1b11a4d1980aaf6046cb2d3a25029a9e87fae675")
(def ^:private b-pub   "30c9b0cba4e38fda13b7166eea8e604e94cfb4322c55124c63a5945bad58c423")
(def ^:private secret  "0e8bd4ae825a73f16f5dfa51388e79e5320a486639181d80ec33cdfe81416568")

(defn- hex [r]
  (if #?(:clj (bytes? r) :cljs (instance? js/Uint8Array r))
    (codec/bytes->hex r)
    ::error))

(deftest x25519-interop-kat
  (let [ap (codec/hex->bytes a-priv) au (codec/hex->bytes a-pub)
        bp (codec/hex->bytes b-priv) bu (codec/hex->bytes b-pub)]
    #?(:clj
       (do
         (is (= secret (hex (a/<!! (dh/key-agreement ap bu)))) "agree(a-priv, b-pub) -> fixed secret")
         (is (= secret (hex (a/<!! (dh/key-agreement bp au)))) "agree(b-priv, a-pub) -> same secret"))
       :cljs
       (async
        done
        (a/go
          (is (= secret (hex (a/<! (dh/key-agreement ap bu)))) "agree(a-priv, b-pub) -> fixed secret")
          (is (= secret (hex (a/<! (dh/key-agreement bp au)))) "agree(b-priv, a-pub) -> same secret")
          (done))))))

(deftest x25519-roundtrip
  #?(:clj
     (let [{ap :private au :public} (a/<!! (dh/generate-keypair))
           {bp :private bu :public} (a/<!! (dh/generate-keypair))
           s-ab (a/<!! (dh/key-agreement ap bu))
           s-ba (a/<!! (dh/key-agreement bp au))]
       (testing "both halves derive the same 32-byte secret"
         (is (= (hex s-ab) (hex s-ba)))
         (is (= 32 (codec/blen s-ab))))
       (testing "a different peer derives a different secret"
         (let [{cp :private} (a/<!! (dh/generate-keypair))]
           (is (not= (hex s-ab) (hex (a/<!! (dh/key-agreement cp au))))))))
     :cljs
     (async
      done
      (a/go
        (let [{ap :private au :public} (a/<! (dh/generate-keypair))
              {bp :private bu :public} (a/<! (dh/generate-keypair))
              s-ab (a/<! (dh/key-agreement ap bu))
              s-ba (a/<! (dh/key-agreement bp au))
              {cp :private} (a/<! (dh/generate-keypair))]
          (is (= (hex s-ab) (hex s-ba)) "both halves agree")
          (is (= 32 (codec/blen s-ab)) "32-byte secret")
          (is (not= (hex s-ab) (hex (a/<! (dh/key-agreement cp au)))) "wrong peer differs")
          (done))))))
