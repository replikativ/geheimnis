(ns org.replikativ.geheimnis.noise
  "The Noise Protocol Framework revision 34, specialized to
   Noise_XX_25519_AESGCM_SHA256.

   The public operations are asynchronous because X25519 and AES-GCM use Web
   Crypto on ClojureScript. `write-message`, `read-message`,
   `encrypt-transport`, `decrypt-transport`, and `rekey` return a core.async
   channel containing either their documented result map or an ExceptionInfo.

   States are single-use. A successful call returns the next state; reusing or
   concurrently using an earlier state is rejected before a nonce can repeat.
   After any operation returns an error, discard the connection and its states.

   This namespace intentionally implements one named suite instead of exposing
   a configurable Noise construction. Protocol names are cryptographic domain
   separators; casually substituting a primitive would define a different
   protocol and risks dangerous cross-protocol interactions."
  (:require [clojure.core.async :as a]
            [org.replikativ.geheimnis.aead :as aead]
            [org.replikativ.geheimnis.codec :as codec]
            [org.replikativ.geheimnis.dh :as dh]
            [org.replikativ.geheimnis.hash :as hash]))

(def protocol-name "Noise_XX_25519_AESGCM_SHA256")
(def max-message-length 65535)

(def ^:private hash-length 32)
(def ^:private dh-length 32)
(def ^:private tag-length 16)
(def ^:private max-word 4294967295)
(def ^:private empty-bytes (codec/zeros 0))

(defn- byte-array? [x]
  #?(:clj (bytes? x) :cljs (instance? js/Uint8Array x)))

(defn- fail [message data]
  (throw (ex-info message (assoc data :type :noise/protocol-error))))

(defn- ensure-bytes [label value]
  (when-not (byte-array? value)
    (fail (str label " must be a byte array") {:field label}))
  value)

(defn- ensure-length [label value expected]
  (ensure-bytes label value)
  (when-not (= expected (codec/blen value))
    (fail (str label " must be " expected " bytes")
          {:field label :expected expected :actual (codec/blen value)}))
  value)

(defn- ensure-keypair [label keypair]
  (when-not (map? keypair)
    (fail (str label " must be a keypair map") {:field label}))
  (ensure-length (str label " public key") (:public keypair) dh-length)
  (ensure-length (str label " private key") (:private keypair) dh-length)
  keypair)

(defn- slice [bs from to]
  #?(:clj (java.util.Arrays/copyOfRange ^bytes bs (int from) (int to))
     :cljs (.slice bs from to)))

(defn- zero-bytes? [bs]
  (every? zero? (map #(bit-and % 0xff) (seq bs))))

(defn- error-value? [x]
  #?(:clj (instance? Throwable x) :cljs (instance? js/Error x)))

(defn- one-byte [value]
  #?(:clj (byte-array [(unchecked-byte value)])
     :cljs (js/Uint8Array. #js [value])))

(defn- unwrap [x context]
  (if (error-value? x)
    (throw (ex-info context {:type :noise/crypto-error} x))
    x))

(defn- fresh-guard [] (atom false))

(defn- consume! [state]
  (when-not (compare-and-set! (::guard state) false true)
    (fail "Noise state has already been consumed"
          {:state-type (::state-type state)})))

(defn- next-state [state updates]
  (assoc (merge state updates) ::guard (fresh-guard)))

(defn- pad-protocol-name []
  (let [name-bytes (codec/str->bytes protocol-name)]
    (if (<= (codec/blen name-bytes) hash-length)
      (codec/concat-bytes
       [name-bytes (codec/zeros (- hash-length (codec/blen name-bytes)))])
      (hash/sha256 name-bytes))))

(defn- mix-hash [symmetric data]
  (assoc symmetric :h (hash/sha256 (codec/concat-bytes [(:h symmetric) data]))))

(defn- hkdf2 [chaining-key input-key-material]
  ;; Noise's HKDF is RFC 5869 with chaining-key as salt and empty info.
  (let [temp-key (hash/hmac-sha256 chaining-key input-key-material)
        output-1 (hash/hmac-sha256 temp-key (one-byte 1))
        output-2 (hash/hmac-sha256
                  temp-key
                  (codec/concat-bytes [output-1 (one-byte 2)]))]
    [output-1 output-2]))

(defn- cipher-state [key]
  {::state-type :cipher
   ::guard (fresh-guard)
   :key key
   :nonce-hi 0
   :nonce-lo 0})

(defn- mix-key [symmetric input-key-material]
  (let [[ck k] (hkdf2 (:ck symmetric) input-key-material)]
    (assoc symmetric :ck ck :cipher (cipher-state k))))

(defn- initialize-symmetric [prologue]
  (let [h (pad-protocol-name)]
    (mix-hash {:ck h :h h :cipher (cipher-state nil)} prologue)))

(defn- set-u8! [out index value]
  #?(:clj (aset ^bytes out (int index) (unchecked-byte value))
     :cljs (aset out index value))
  out)

(defn- encode-word-be! [out offset word]
  (doseq [i (range 4)]
    (set-u8! out (+ offset i)
             (mod (quot word (Math/pow 256 (- 3 i))) 256)))
  out)

(defn- nonce-bytes [{:keys [nonce-hi nonce-lo]}]
  ;; AESGCM uses 32 zero bits followed by the 64-bit Noise nonce in big endian.
  (let [out (codec/zeros 12)]
    (encode-word-be! out 4 nonce-hi)
    (encode-word-be! out 8 nonce-lo)))

(defn- increment-nonce [cipher]
  (let [{:keys [nonce-hi nonce-lo]} cipher]
    (when (and (= nonce-hi max-word) (= nonce-lo max-word))
      (fail "Noise nonce is exhausted" {:nonce-hi nonce-hi :nonce-lo nonce-lo}))
    (if (= nonce-lo max-word)
      (assoc cipher :nonce-hi (inc nonce-hi) :nonce-lo 0)
      (assoc cipher :nonce-lo (inc nonce-lo)))))

(defn- has-key? [cipher] (some? (:key cipher)))

(defn- cipher-encrypt [cipher aad plaintext]
  (a/go
    (try
      (if-not (has-key? cipher)
        {:cipher cipher :ciphertext plaintext}
        (let [ciphertext (unwrap
                          (a/<! (aead/aead-encrypt (:key cipher)
                                                   (nonce-bytes cipher)
                                                   aad plaintext))
                          "Noise encryption failed")]
          {:cipher (increment-nonce cipher) :ciphertext ciphertext}))
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn- cipher-decrypt [cipher aad ciphertext]
  (a/go
    (try
      (if-not (has-key? cipher)
        {:cipher cipher :plaintext ciphertext}
        (let [plaintext (unwrap
                         (a/<! (aead/aead-decrypt (:key cipher)
                                                  (nonce-bytes cipher)
                                                  aad ciphertext))
                         "Noise authentication failed")]
          {:cipher (increment-nonce cipher) :plaintext plaintext}))
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn- encrypt-and-hash [symmetric plaintext]
  (a/go
    (try
      (let [{:keys [cipher ciphertext]}
            (unwrap (a/<! (cipher-encrypt (:cipher symmetric)
                                          (:h symmetric) plaintext))
                    "Noise EncryptAndHash failed")]
        {:symmetric (-> symmetric
                        (assoc :cipher cipher)
                        (mix-hash ciphertext))
         :ciphertext ciphertext})
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn- decrypt-and-hash [symmetric ciphertext]
  (a/go
    (try
      (let [{:keys [cipher plaintext]}
            (unwrap (a/<! (cipher-decrypt (:cipher symmetric)
                                          (:h symmetric) ciphertext))
                    "Noise DecryptAndHash failed")]
        {:symmetric (-> symmetric
                        (assoc :cipher cipher)
                        (mix-hash ciphertext))
         :plaintext plaintext})
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn- checked-dh [private-key public-key context]
  (a/go
    (try
      (let [secret (unwrap (a/<! (dh/key-agreement private-key public-key)) context)]
        (when (zero-bytes? secret)
          (fail "X25519 produced the forbidden all-zero output" {:context context}))
        secret)
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn- ensure-ephemeral [state]
  (a/go
    (try
      (if (:e state)
        state
        (let [keypair (unwrap (a/<! (dh/generate-keypair))
                              "Noise ephemeral key generation failed")]
          (next-state state {:e (ensure-keypair "ephemeral" keypair)})))
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn- checked-message [parts]
  (let [message (codec/concat-bytes parts)]
    (when (> (codec/blen message) max-message-length)
      (fail "Noise message exceeds 65535 bytes"
            {:actual (codec/blen message) :maximum max-message-length}))
    message))

(defn- split [symmetric role]
  (let [[k1 k2] (hkdf2 (:ck symmetric) empty-bytes)
        [send receive] (if (= role :initiator) [k1 k2] [k2 k1])]
    {:send (cipher-state send) :receive (cipher-state receive)}))

(defn initialize
  "Initialize a Noise XX handshake state.

   `role` is `:initiator` or `:responder`. `static-keypair` contains raw X25519
   `:public` and `:private` 32-byte values. Options:

   * `:prologue` - bytes agreed by both parties (defaults to empty)
   * `:ephemeral-keypair` - fixed raw keypair for deterministic tests only

   Production callers should let the implementation generate ephemeral keys."
  ([role static-keypair] (initialize role static-keypair {}))
  ([role static-keypair {:keys [prologue ephemeral-keypair]
                         :or {prologue empty-bytes}}]
   (when-not (#{:initiator :responder} role)
     (fail "Noise role must be :initiator or :responder" {:role role}))
   (ensure-keypair "static" static-keypair)
   (ensure-bytes "prologue" prologue)
   (when ephemeral-keypair (ensure-keypair "ephemeral" ephemeral-keypair))
   {::state-type :handshake
    ::guard (fresh-guard)
    :role role
    :step 0
    :s static-keypair
    :e ephemeral-keypair
    :rs nil
    :re nil
    :symmetric (initialize-symmetric prologue)
    :complete? false
    :transport nil}))

(defn handshake-complete? [state]
  (true? (:complete? state)))

(defn handshake-hash
  "Return the current transcript hash. After completion this is suitable for
   channel binding."
  [state]
  (get-in state [:symmetric :h]))

(defn remote-static-key
  "Return the authenticated remote static X25519 public key once received."
  [state]
  (:rs state))

(defn transport-ciphers
  "Return independent `:send` and `:receive` CipherStates after completion."
  [state]
  (when-not (handshake-complete? state)
    (fail "Noise handshake is not complete" {}))
  (:transport state))

(defn write-message
  "Write the next handshake message with `payload` bytes. Returns a channel of
   `{:state next-state :message bytes}` or an ExceptionInfo."
  [state payload]
  (a/go
    (try
      (consume! state)
      (ensure-bytes "payload" payload)
      (when (:complete? state) (fail "Noise handshake is already complete" {}))
      (let [{:keys [role step]} state]
        (cond
          (and (= role :initiator) (= step 0))
          (let [state (unwrap (a/<! (ensure-ephemeral state))
                              "Noise ephemeral key generation failed")
                sym (mix-hash (:symmetric state) (get-in state [:e :public]))
                {:keys [symmetric ciphertext]}
                (unwrap (a/<! (encrypt-and-hash sym payload))
                        "Noise first message encryption failed")]
            {:state (next-state state {:step 1 :symmetric symmetric})
             :message (checked-message [(get-in state [:e :public]) ciphertext])})

          (and (= role :responder) (= step 1))
          (let [state (unwrap (a/<! (ensure-ephemeral state))
                              "Noise ephemeral key generation failed")
                sym-0 (mix-hash (:symmetric state) (get-in state [:e :public]))
                ee (unwrap (a/<! (checked-dh (get-in state [:e :private]) (:re state)
                                             "Noise XX ee failed"))
                           "Noise XX ee failed")
                sym-1 (mix-key sym-0 ee)
                static-result (unwrap
                               (a/<! (encrypt-and-hash sym-1 (get-in state [:s :public])))
                               "Noise static key encryption failed")
                es (unwrap (a/<! (checked-dh (get-in state [:s :private]) (:re state)
                                             "Noise XX es failed"))
                           "Noise XX es failed")
                sym-2 (mix-key (:symmetric static-result) es)
                payload-result (unwrap (a/<! (encrypt-and-hash sym-2 payload))
                                       "Noise second payload encryption failed")]
            {:state (next-state state {:step 2 :symmetric (:symmetric payload-result)})
             :message (checked-message [(get-in state [:e :public])
                                        (:ciphertext static-result)
                                        (:ciphertext payload-result)])})

          (and (= role :initiator) (= step 2))
          (let [static-result (unwrap
                               (a/<! (encrypt-and-hash (:symmetric state)
                                                       (get-in state [:s :public])))
                               "Noise static key encryption failed")
                se (unwrap (a/<! (checked-dh (get-in state [:s :private]) (:re state)
                                             "Noise XX se failed"))
                           "Noise XX se failed")
                sym (mix-key (:symmetric static-result) se)
                payload-result (unwrap (a/<! (encrypt-and-hash sym payload))
                                       "Noise third payload encryption failed")
                final-sym (:symmetric payload-result)]
            {:state (next-state state {:step 3
                                       :symmetric final-sym
                                       :complete? true
                                       :transport (split final-sym role)})
             :message (checked-message [(:ciphertext static-result)
                                        (:ciphertext payload-result)])})

          :else
          (fail "Noise handshake write called out of turn" {:role role :step step})))
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn read-message
  "Read the next handshake `message`. Returns a channel of
   `{:state next-state :payload bytes}` or an ExceptionInfo."
  [state message]
  (a/go
    (try
      (consume! state)
      (ensure-bytes "message" message)
      (when (> (codec/blen message) max-message-length)
        (fail "Noise message exceeds 65535 bytes"
              {:actual (codec/blen message) :maximum max-message-length}))
      (when (:complete? state) (fail "Noise handshake is already complete" {}))
      (let [{:keys [role step]} state
            n (codec/blen message)]
        (cond
          (and (= role :responder) (= step 0))
          (do
            (when (< n dh-length)
              (fail "Truncated Noise XX first message" {:actual n :minimum dh-length}))
            (let [re (slice message 0 dh-length)
                  ciphertext (slice message dh-length n)
                  sym (mix-hash (:symmetric state) re)
                  result (unwrap (a/<! (decrypt-and-hash sym ciphertext))
                                 "Noise first payload decryption failed")]
              {:state (next-state state {:step 1 :re re :symmetric (:symmetric result)})
               :payload (:plaintext result)}))

          (and (= role :initiator) (= step 1))
          (do
            (when (< n (+ dh-length dh-length tag-length tag-length))
              (fail "Truncated Noise XX second message"
                    {:actual n :minimum (+ dh-length dh-length tag-length tag-length)}))
            (let [re (slice message 0 dh-length)
                  encrypted-static (slice message dh-length (+ dh-length dh-length tag-length))
                  encrypted-payload (slice message (+ dh-length dh-length tag-length) n)
                  sym-0 (mix-hash (:symmetric state) re)
                  ee (unwrap (a/<! (checked-dh (get-in state [:e :private]) re
                                               "Noise XX ee failed"))
                             "Noise XX ee failed")
                  sym-1 (mix-key sym-0 ee)
                  static-result (unwrap (a/<! (decrypt-and-hash sym-1 encrypted-static))
                                        "Noise static key decryption failed")
                  rs (:plaintext static-result)
                  _ (ensure-length "remote static key" rs dh-length)
                  es (unwrap (a/<! (checked-dh (get-in state [:e :private]) rs
                                               "Noise XX es failed"))
                             "Noise XX es failed")
                  sym-2 (mix-key (:symmetric static-result) es)
                  payload-result (unwrap (a/<! (decrypt-and-hash sym-2 encrypted-payload))
                                         "Noise second payload decryption failed")]
              {:state (next-state state {:step 2 :re re :rs rs
                                         :symmetric (:symmetric payload-result)})
               :payload (:plaintext payload-result)}))

          (and (= role :responder) (= step 2))
          (do
            (when (< n (+ dh-length tag-length tag-length))
              (fail "Truncated Noise XX third message"
                    {:actual n :minimum (+ dh-length tag-length tag-length)}))
            (let [encrypted-static (slice message 0 (+ dh-length tag-length))
                  encrypted-payload (slice message (+ dh-length tag-length) n)
                  static-result (unwrap
                                 (a/<! (decrypt-and-hash (:symmetric state) encrypted-static))
                                 "Noise static key decryption failed")
                  rs (:plaintext static-result)
                  _ (ensure-length "remote static key" rs dh-length)
                  se (unwrap (a/<! (checked-dh (get-in state [:e :private]) rs
                                               "Noise XX se failed"))
                             "Noise XX se failed")
                  sym (mix-key (:symmetric static-result) se)
                  payload-result (unwrap (a/<! (decrypt-and-hash sym encrypted-payload))
                                         "Noise third payload decryption failed")
                  final-sym (:symmetric payload-result)]
              {:state (next-state state {:step 3 :rs rs
                                         :symmetric final-sym
                                         :complete? true
                                         :transport (split final-sym role)})
               :payload (:plaintext payload-result)}))

          :else
          (fail "Noise handshake read called out of turn" {:role role :step step})))
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn encrypt-transport
  "Encrypt one transport payload. The returned `:cipher` must replace the input
   cipher before another message is encrypted."
  [cipher plaintext]
  (a/go
    (try
      (consume! cipher)
      (ensure-bytes "plaintext" plaintext)
      (when (> (codec/blen plaintext) (- max-message-length tag-length))
        (fail "Noise transport plaintext exceeds 65519 bytes"
              {:actual (codec/blen plaintext) :maximum (- max-message-length tag-length)}))
      (let [{next-cipher :cipher message :ciphertext}
            (unwrap (a/<! (cipher-encrypt cipher empty-bytes plaintext))
                    "Noise transport encryption failed")]
        {:cipher (next-state next-cipher {}) :message message})
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn decrypt-transport
  "Authenticate and decrypt one transport message. The returned `:cipher` must
   replace the input cipher before another message is decrypted."
  [cipher message]
  (a/go
    (try
      (consume! cipher)
      (ensure-bytes "message" message)
      (when (or (< (codec/blen message) tag-length)
                (> (codec/blen message) max-message-length))
        (fail "Invalid Noise transport message length"
              {:actual (codec/blen message) :minimum tag-length
               :maximum max-message-length}))
      (let [{next-cipher :cipher plaintext :plaintext}
            (unwrap (a/<! (cipher-decrypt cipher empty-bytes message))
                    "Noise transport authentication failed")]
        {:cipher (next-state next-cipher {}) :payload plaintext})
      (catch #?(:clj Throwable :cljs :default) e e))))

(defn rekey
  "Apply Noise `REKEY(k)` to one transport CipherState. The nonce is preserved,
   as required by revision 34. Returns a channel containing the new CipherState
   or an ExceptionInfo."
  [cipher]
  (a/go
    (try
      (consume! cipher)
      (when-not (has-key? cipher) (fail "Cannot rekey an empty CipherState" {}))
      (let [reserved (assoc cipher :nonce-hi max-word :nonce-lo max-word)
            encrypted (unwrap
                       (a/<! (aead/aead-encrypt (:key cipher)
                                                (nonce-bytes reserved)
                                                empty-bytes
                                                (codec/zeros 32)))
                       "Noise rekey failed")]
        (next-state cipher {:key (codec/sub-bytes encrypted 32)}))
      (catch #?(:clj Throwable :cljs :default) e e))))
