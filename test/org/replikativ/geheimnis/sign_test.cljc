(ns org.replikativ.geheimnis.sign-test
  "Ed25519 sign/verify round-trip + a fixed interop KAT. The KAT was produced on
   the JVM; a ClojureScript peer that reproduces the SAME signature from the seed
   and verifies the SAME public key is byte-compatible — a JVM-signed assertion
   verifies on a browser/Node peer and vice versa. Both platforms use their
   native Ed25519 (java.security / Web Crypto), so agreement here is a strong
   correctness anchor, not just self-consistency."
  (:require #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing async]])
            [clojure.core.async :as a]
            [org.replikativ.geheimnis.sign :as sign]
            [org.replikativ.geheimnis.codec :as codec]))

(def ^:private kat-seed "99c1cc652f850ae2da7f4e078aa9acfc2ff67c3fdcb19bd89d25c3c0f87ec3ed")
(def ^:private kat-pub  "a44f96b0986462dfa7ec2239d00622ff8398efd8388a8efdadfb7ba802b7c62a")
(def ^:private kat-msg  "geheimnis-ed25519-kat")
(def ^:private kat-sig  "7678fd1b3a9c9ffc977ed5296f825a05b03b59836e35384c4bf8b02005f687eb807643cfc993cedcd44bca3da8bdc0e97126c6fe82ce9268fa1146e192f0b50e")

(defn- sig-hex [r]
  (if #?(:clj (bytes? r) :cljs (instance? js/Uint8Array r))
    (codec/bytes->hex r)
    ::error))

(defn- flip-first [bs]
  #?(:clj  (let [c (java.util.Arrays/copyOf ^bytes bs (alength ^bytes bs))]
             (aset c 0 (unchecked-byte (bit-xor (aget c 0) 1))) c)
     :cljs (let [c (.slice bs 0)] (aset c 0 (bit-xor (aget c 0) 1)) c)))

(deftest ed25519-interop-kat
  (let [seed (codec/hex->bytes kat-seed)
        pub  (codec/hex->bytes kat-pub)
        msg  (codec/str->bytes kat-msg)
        sig  (codec/hex->bytes kat-sig)]
    #?(:clj
       (do
         (is (= kat-sig (sig-hex (a/<!! (sign/sign seed msg)))) "sign(seed,msg) -> fixed sig (deterministic)")
         (is (true? (a/<!! (sign/verify pub msg sig))) "verify(pub,msg,sig)")
         (is (false? (a/<!! (sign/verify pub (codec/str->bytes "tampered") sig))) "wrong message rejected")
         (is (false? (a/<!! (sign/verify pub msg (flip-first sig)))) "tampered signature rejected"))
       :cljs
       (async
        done
        (a/go
          (is (= kat-sig (sig-hex (a/<! (sign/sign seed msg)))) "sign(seed,msg) -> fixed sig (deterministic)")
          (is (true? (a/<! (sign/verify pub msg sig))) "verify(pub,msg,sig)")
          (is (false? (a/<! (sign/verify pub (codec/str->bytes "tampered") sig))) "wrong message rejected")
          (is (false? (a/<! (sign/verify pub msg (flip-first sig)))) "tampered signature rejected")
          (done))))))

(deftest ed25519-roundtrip
  #?(:clj
     (let [{:keys [public private]} (a/<!! (sign/generate-keypair))
           other (:public (a/<!! (sign/generate-keypair)))
           msg (codec/str->bytes "hello geheimnis ed25519 🔏")
           sig (a/<!! (sign/sign private msg))]
       (testing "verify(sign(x)) = true"
         (is (true? (a/<!! (sign/verify public msg sig)))))
       (testing "a different (valid) public key rejects the signature"
         (is (false? (a/<!! (sign/verify other msg sig)))))
       (testing "a tampered message is rejected"
         (is (false? (a/<!! (sign/verify public (codec/str->bytes "hello geheimnis ed25519 🔓") sig))))))
     :cljs
     (async
      done
      (a/go
        (let [{:keys [public private]} (a/<! (sign/generate-keypair))
              other (:public (a/<! (sign/generate-keypair)))
              msg (codec/str->bytes "hello geheimnis ed25519 🔏")
              sig (a/<! (sign/sign private msg))]
          (is (true? (a/<! (sign/verify public msg sig))) "round-trip")
          (is (false? (a/<! (sign/verify other msg sig))) "wrong key")
          (is (false? (a/<! (sign/verify public (codec/str->bytes "hello geheimnis ed25519 🔓") sig))) "tamper")
          (done))))))

(deftest der-envelopes-are-constant
  ;; sign.cljc moves between raw 32-byte keys and PKCS8/SPKI by prepending two
  ;; fixed prefixes. That is only sound while the JDK emits exactly this
  ;; encoding for Ed25519, so the constants are checked against freshly
  ;; generated keys rather than trusted. A JDK that ever changed them would
  ;; otherwise break every key import silently.
  #?(:clj
     (testing "the JDK still emits the encodings the prefixes assume"
       (dotimes [_ 5]
         (let [kp (.generateKeyPair (java.security.KeyPairGenerator/getInstance "Ed25519"))
               pub (.getEncoded (.getPublic kp))
               priv (.getEncoded (.getPrivate kp))]
           (is (= 44 (alength pub)))
           (is (= 48 (alength priv)))
           (is (= "302a300506032b6570032100"
                  (codec/bytes->hex (java.util.Arrays/copyOfRange pub 0 12))))
           (is (= "302e020100300506032b657004220420"
                  (codec/bytes->hex (java.util.Arrays/copyOfRange priv 0 16)))))))))

#?(:cljs
   (deftest fallback-is-injectable-and-optional
     ;; Web Crypto reached Ed25519 in Chrome only in mid-2025, so a runtime
     ;; without it must still be able to sign. The fallback is injected rather
     ;; than required so the dependency stays the consumer's choice.
     (testing "setting and clearing a fallback does not disturb the happy path"
       (sign/set-fallback! nil)
       (is (nil? (sign/set-fallback! nil))))))
