(ns native-image-random
  "AOT/native-image regression: namespace loading must not initialize the RNG."
  (:require [org.replikativ.geheimnis.core :as core])
  (:gen-class))

(defn -main [& _]
  (let [rng @(ns-resolve 'org.replikativ.geheimnis.core 'secure-random)]
    (assert (not (realized? rng)) "RNG initialized before runtime use")
    (let [^bytes a (core/random-bytes 32)
          ^bytes b (core/random-bytes 32)]
      (assert (realized? rng))
      (assert (= 32 (alength a) (alength b)))
      (assert (not (core/ct-equal? a b)))
      ;; Allows the runner to compare separate processes, not merely two calls.
      (println (apply str (map #(format "%02x" (bit-and 255 %)) a))))))
