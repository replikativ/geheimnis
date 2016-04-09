(ns geheimnis.base64
  (:require #?(:clj [clojure.data.codec.base64 :as b64]
               :cljs [goog.crypt.base64])
            #?(:cljs [cljs.reader :as r])))

(deftype Base64 [s])

(defn encode
  "Returns a base64 encoded String."
  [byte-arr]
  #?(:clj (Base64. (String. (b64/encode byte-arr) "UTF-8"))
     :cljs (Base64. (goog.crypt.base64.encodeByteArray byte-arr))))


(defn decode
  "Returns a byte-array for encoded String."
  [base64]
  (let [s (.-s base64)]
    #?(:clj (b64/decode (.getBytes s "UTF-8"))
       :cljs (goog.crypt.base64.decodeStringToByteArray s))))

(defn base64->BigInt
  [base64]
  (let [d (decode base64)]
    #?(:clj (BigInteger. d)
       :cljs (js/BigInteger. d))))



#?(:clj
   (defmethod print-method geheimnis.base64.Base64
     [v ^java.io.Writer w]
     (.write w (str "#geheimnis/Base64 " (pr-str (.-s v)))))
   :cljs
   (extend-type Base64
     IPrintWithWriter
     (-pr-writer [this writer _] (-write writer (str "#geheimnis/Base64 " (pr-str (.-s this)))))))

(defn str->base64 [s]
  (Base64. s))

#?(:cljs
   (r/register-tag-parser! 'geheimnis/Base64 (fn [s] (js/BigInteger. s))))


(comment
  (vec (decode (encode (clj->js (range 10))))))
