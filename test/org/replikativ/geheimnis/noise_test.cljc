(ns org.replikativ.geheimnis.noise-test
  "Cross-platform tests for Noise_XX_25519_AESGCM_SHA256.

   The known-answer case is copied from Cacophony's independently generated
   public-domain `vectors/cacophony.txt`:
   https://github.com/haskell-cryptography/cacophony/blob/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/vectors/cacophony.txt"
  (:require #?(:clj [clojure.test :refer [deftest is testing]]
               :cljs [cljs.test :refer-macros [deftest is testing async]])
            [clojure.core.async :as a]
            [org.replikativ.geheimnis.codec :as codec]
            [org.replikativ.geheimnis.dh :as dh]
            [org.replikativ.geheimnis.noise :as noise]))

(def ^:private reference-vector
  {:prologue "4a6f686e2047616c74"
   :initiator-static "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"
   :initiator-ephemeral "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
   :responder-static "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"
   :responder-ephemeral "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
   :handshake-hash "1b7aefb1125762aa21a252890d00af54519638b76437444538f9a52f21e2e0dc"
   :messages
   [{:payload "4c756477696720766f6e204d69736573"
     :ciphertext (str "ca35def5ae56cec33dc2036731ab14896"
                      "bc4c75dbb07a61f879f8e3afa4c7944"
                      "4c756477696720766f6e204d69736573")}
    {:payload "4d757272617920526f746862617264"
     :ciphertext (str "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"
                      "757117acceb05bd7a45733bc22015c97a9d0cbaf41b80446d5988ff5127235d7"
                      "6b79eade70f473d6a4ef521fdcbeda5340d01e028ba793fc059f2724a83af05f1"
                      "2dda0448a7621a926b379a92477fd")}
    {:payload "462e20412e20486179656b"
     :ciphertext (str "c90f1cf77eba4e50edb038991565e36c9758943a989229b6051244dc4fbecb69"
                      "46744b401af2ee1a5881b65fbb87fd07cb6a328ececc9ce6ce84c399dc332d4f"
                      "d521fa4bb7f467ce909395")}
    {:payload "4361726c204d656e676572"
     :ciphertext "bc3fa77f6aca3e8466d7dc6bea10013e88a6a29add5132b461806c"}
    {:payload "4a65616e2d426170746973746520536179"
     :ciphertext "250b01074cdfe0df2ecf8ccbf1737b15a2ddb5b52fd9a396604e9c793cee3b3bb9"}
    {:payload "457567656e2042f6686d20766f6e2042617765726b"
     :ciphertext "449d4d433b3cdc3d02bf6fc881774b9df54366ebcffb9689bb13f14709822cd7ef42bcdb4d"}]})

(def ^:private x25519-basepoint
  (codec/hex->bytes
   "0900000000000000000000000000000000000000000000000000000000000000"))

(defn- error-value? [x]
  #?(:clj (instance? Throwable x) :cljs (instance? js/Error x)))

(defn- unwrap [x]
  (when (error-value? x) (throw x))
  x)

(defn- verify! [condition label]
  (when-not condition
    (throw (ex-info (str "Noise test check failed: " label) {:check label})))
  true)

(defn- keypair-from-private [private-hex]
  (a/go
    (let [private (codec/hex->bytes private-hex)
          public (unwrap (a/<! (dh/key-agreement private x25519-basepoint)))]
      {:private private :public public})))

(defn- bytes= [left right]
  (= (codec/bytes->hex left) (codec/bytes->hex right)))

(defn- flip-first [bs]
  #?(:clj (let [copy (java.util.Arrays/copyOf ^bytes bs (alength ^bytes bs))]
            (aset copy 0 (unchecked-byte (bit-xor (aget copy 0) 1)))
            copy)
     :cljs (let [copy (.slice bs 0)]
             (aset copy 0 (bit-xor (aget copy 0) 1))
             copy)))

(defn- exercise-reference-vector []
  (a/go
    (try
      (let [is (a/<! (keypair-from-private (:initiator-static reference-vector)))
            ie (a/<! (keypair-from-private (:initiator-ephemeral reference-vector)))
            rs (a/<! (keypair-from-private (:responder-static reference-vector)))
            re (a/<! (keypair-from-private (:responder-ephemeral reference-vector)))
            prologue (codec/hex->bytes (:prologue reference-vector))
            init-0 (noise/initialize :initiator is {:prologue prologue
                                                    :ephemeral-keypair ie})
            resp-0 (noise/initialize :responder rs {:prologue prologue
                                                    :ephemeral-keypair re})
            [m1 m2 m3 m4 m5 m6] (:messages reference-vector)

            i1 (unwrap (a/<! (noise/write-message init-0 (codec/hex->bytes (:payload m1)))))
            _ (verify! (= (:ciphertext m1) (codec/bytes->hex (:message i1)))
                       "reference handshake message 1")
            r1 (unwrap (a/<! (noise/read-message resp-0 (:message i1))))
            _ (verify! (= (:payload m1) (codec/bytes->hex (:payload r1)))
                       "reference handshake payload 1")

            r2 (unwrap (a/<! (noise/write-message (:state r1) (codec/hex->bytes (:payload m2)))))
            _ (verify! (= (:ciphertext m2) (codec/bytes->hex (:message r2)))
                       "reference handshake message 2")
            i2 (unwrap (a/<! (noise/read-message (:state i1) (:message r2))))
            _ (verify! (= (:payload m2) (codec/bytes->hex (:payload i2)))
                       "reference handshake payload 2")

            i3 (unwrap (a/<! (noise/write-message (:state i2) (codec/hex->bytes (:payload m3)))))
            _ (verify! (= (:ciphertext m3) (codec/bytes->hex (:message i3)))
                       "reference handshake message 3")
            r3 (unwrap (a/<! (noise/read-message (:state r2) (:message i3))))
            _ (verify! (= (:payload m3) (codec/bytes->hex (:payload r3)))
                       "reference handshake payload 3")
            init-final (:state i3)
            resp-final (:state r3)

            init-ciphers (noise/transport-ciphers init-final)
            resp-ciphers (noise/transport-ciphers resp-final)
            r4 (unwrap (a/<! (noise/encrypt-transport (:send resp-ciphers)
                                                      (codec/hex->bytes (:payload m4)))))
            _ (verify! (= (:ciphertext m4) (codec/bytes->hex (:message r4)))
                       "reference responder transport message")
            i4 (unwrap (a/<! (noise/decrypt-transport (:receive init-ciphers) (:message r4))))
            _ (verify! (= (:payload m4) (codec/bytes->hex (:payload i4)))
                       "reference responder transport payload")

            i5 (unwrap (a/<! (noise/encrypt-transport (:send init-ciphers)
                                                      (codec/hex->bytes (:payload m5)))))
            _ (verify! (= (:ciphertext m5) (codec/bytes->hex (:message i5)))
                       "reference initiator transport message")
            r5 (unwrap (a/<! (noise/decrypt-transport (:receive resp-ciphers) (:message i5))))
            _ (verify! (= (:payload m5) (codec/bytes->hex (:payload r5)))
                       "reference initiator transport payload")

            r6 (unwrap (a/<! (noise/encrypt-transport (:cipher r4)
                                                      (codec/hex->bytes (:payload m6)))))
            _ (verify! (= (:ciphertext m6) (codec/bytes->hex (:message r6)))
                       "reference second responder transport message")
            i6 (unwrap (a/<! (noise/decrypt-transport (:cipher i4) (:message r6))))]
        (verify! (= (:payload m6) (codec/bytes->hex (:payload i6)))
                 "reference second responder transport payload")
        (verify! (= (:handshake-hash reference-vector)
                    (codec/bytes->hex (noise/handshake-hash init-final)))
                 "initiator handshake hash")
        (verify! (= (:handshake-hash reference-vector)
                    (codec/bytes->hex (noise/handshake-hash resp-final)))
                 "responder handshake hash")
        (verify! (bytes= (:public rs) (noise/remote-static-key init-final))
                 "initiator authenticates responder static key")
        (verify! (bytes= (:public is) (noise/remote-static-key resp-final))
                 "responder authenticates initiator static key")
        true)
      (catch #?(:clj Throwable :cljs :default) e e))))

(deftest cacophony-reference-vector
  #?(:clj (is (true? (a/<!! (exercise-reference-vector))))
     :cljs (async done
                  (a/go
                    (is (true? (a/<! (exercise-reference-vector))))
                    (done)))))

(defn- exercise-roundtrip-and-failures []
  (a/go
    (try
      (let [is (unwrap (a/<! (dh/generate-keypair)))
            rs (unwrap (a/<! (dh/generate-keypair)))
            prologue (codec/str->bytes "netz/noise/v1")
            init-0 (noise/initialize :initiator is {:prologue prologue})
            resp-0 (noise/initialize :responder rs {:prologue prologue})
            i1 (unwrap (a/<! (noise/write-message init-0 (codec/str->bytes "one"))))
            reused (a/<! (noise/write-message init-0 (codec/str->bytes "nonce reuse")))
            r1 (unwrap (a/<! (noise/read-message resp-0 (:message i1))))
            r2 (unwrap (a/<! (noise/write-message (:state r1) (codec/str->bytes "two"))))
            i2 (unwrap (a/<! (noise/read-message (:state i1) (:message r2))))
            i3 (unwrap (a/<! (noise/write-message (:state i2) (codec/str->bytes "three"))))
            r3 (unwrap (a/<! (noise/read-message (:state r2) (:message i3))))
            ic (noise/transport-ciphers (:state i3))
            rc (noise/transport-ciphers (:state r3))
            sent (unwrap (a/<! (noise/encrypt-transport (:send ic)
                                                        (codec/str->bytes "hello transport"))))
            received (unwrap (a/<! (noise/decrypt-transport (:receive rc) (:message sent))))
            rekeyed-send (unwrap (a/<! (noise/rekey (:cipher sent))))
            rekeyed-receive (unwrap (a/<! (noise/rekey (:cipher received))))
            sent-after-rekey (unwrap
                              (a/<! (noise/encrypt-transport
                                     rekeyed-send (codec/str->bytes "after rekey"))))
            received-after-rekey (unwrap
                                  (a/<! (noise/decrypt-transport
                                         rekeyed-receive (:message sent-after-rekey))))
            tampered-send (unwrap
                           (a/<! (noise/encrypt-transport
                                  (:cipher sent-after-rekey)
                                  (codec/str->bytes "tamper me"))))
            tampered-result (a/<! (noise/decrypt-transport
                                   (:cipher received-after-rekey)
                                   (flip-first (:message tampered-send))))
            oversized-handshake (a/<! (noise/write-message
                                       (noise/initialize :initiator is)
                                       (codec/zeros 65504)))
            oversized-input (a/<! (noise/read-message
                                   (noise/initialize :responder rs)
                                   (codec/zeros 65536)))
            oversized-transport (a/<! (noise/encrypt-transport
                                       (:send rc) (codec/zeros 65520)))]
        (verify! (error-value? reused) "handshake states cannot be reused")
        (verify! (= "one" (codec/bytes->str (:payload r1))) "payload one")
        (verify! (= "two" (codec/bytes->str (:payload i2))) "payload two")
        (verify! (= "three" (codec/bytes->str (:payload r3))) "payload three")
        (verify! (= "hello transport" (codec/bytes->str (:payload received)))
                 "transport roundtrip")
        (verify! (= "after rekey" (codec/bytes->str (:payload received-after-rekey)))
                 "transport rekey roundtrip")
        (verify! (error-value? tampered-result) "transport authentication")
        (verify! (error-value? oversized-handshake) "handshake output bound")
        (verify! (error-value? oversized-input) "handshake input bound")
        (verify! (error-value? oversized-transport) "transport payload bound")
        (verify! (noise/handshake-complete? (:state i3)) "initiator complete")
        (verify! (noise/handshake-complete? (:state r3)) "responder complete")
        true)
      (catch #?(:clj Throwable :cljs :default) e e))))

(deftest generated-roundtrip-and-single-use-state
  #?(:clj (is (true? (a/<!! (exercise-roundtrip-and-failures))))
     :cljs (async done
                  (a/go
                    (is (true? (a/<! (exercise-roundtrip-and-failures))))
                    (done)))))

(defn- exercise-tamper-rejection []
  (a/go
    (try
      (let [is (unwrap (a/<! (dh/generate-keypair)))
            rs (unwrap (a/<! (dh/generate-keypair)))
            init-0 (noise/initialize :initiator is)
            resp-0 (noise/initialize :responder rs)
            i1 (unwrap (a/<! (noise/write-message init-0 (codec/zeros 0))))
            r1 (unwrap (a/<! (noise/read-message resp-0 (:message i1))))
            r2 (unwrap (a/<! (noise/write-message (:state r1) (codec/zeros 0))))
            result (a/<! (noise/read-message (:state i1) (flip-first (:message r2))))]
        (verify! (error-value? result) "tampered transcript is rejected")
        true)
      (catch #?(:clj Throwable :cljs :default) e e))))

(deftest transcript-tamper-is-rejected
  #?(:clj (is (true? (a/<!! (exercise-tamper-rejection))))
     :cljs (async done
                  (a/go
                    (is (true? (a/<! (exercise-tamper-rejection))))
                    (done)))))

(defn- exercise-concurrent-send-ownership []
  (a/go
    (try
      (let [is (unwrap (a/<! (dh/generate-keypair)))
            rs (unwrap (a/<! (dh/generate-keypair)))
            init-0 (noise/initialize :initiator is)
            resp-0 (noise/initialize :responder rs)
            i1 (unwrap (a/<! (noise/write-message init-0 (codec/zeros 0))))
            r1 (unwrap (a/<! (noise/read-message resp-0 (:message i1))))
            r2 (unwrap (a/<! (noise/write-message (:state r1) (codec/zeros 0))))
            i2 (unwrap (a/<! (noise/read-message (:state i1) (:message r2))))
            i3 (unwrap (a/<! (noise/write-message (:state i2) (codec/zeros 0))))
            r3 (unwrap (a/<! (noise/read-message (:state r2) (:message i3))))
            init-ciphers (noise/transport-ciphers (:state i3))
            resp-ciphers (noise/transport-ciphers (:state r3))
            ;; Construct both operations before taking either result. The
            ;; CipherState guard must atomically grant ownership to only one.
            first-op (noise/encrypt-transport (:send init-ciphers)
                                              (codec/str->bytes "first"))
            second-op (noise/encrypt-transport (:send init-ciphers)
                                               (codec/str->bytes "second"))
            results [(a/<! first-op) (a/<! second-op)]
            successes (remove error-value? results)
            failures (filter error-value? results)
            winner (first successes)
            received (unwrap (a/<! (noise/decrypt-transport
                                    (:receive resp-ciphers) (:message winner))))]
        (verify! (= 1 (count successes)) "exactly one concurrent send succeeds")
        (verify! (= 1 (count failures)) "concurrent state reuse is rejected")
        (verify! (contains? #{"first" "second"}
                            (codec/bytes->str (:payload received)))
                 "winning concurrent payload decrypts")
        true)
      (catch #?(:clj Throwable :cljs :default) e e))))

(deftest concurrent-send-cannot-reuse-a-nonce
  #?(:clj (is (true? (a/<!! (exercise-concurrent-send-ownership))))
     :cljs (async done
                  (a/go
                    (is (true? (a/<! (exercise-concurrent-send-ownership))))
                    (done)))))
