(ns geheimnis.core-test
  (:require [cljs.test :refer-macros [deftest is testing run-tests]]
            [geheimnis.aes :as aes]
            [geheimnis.base64 :as b64]
            [geheimnis.md5 :as md5]))

(enable-console-print!)

#_(deftest aes-test
  (testing "AES tests."
    (is (= [7 7 7 7 7 7 7 7 7 7]
           (vec (aes/decrypt "foo" (aes/encrypt "foo" (aes/byte-array (repeat 10 7)))))))
    (is (= (vec (aes/encrypt "foo" (aes/byte-array (repeat 10 7))))
           [-70 -83 -75 9 -46 -97 70 -89 -124 80 -99 -15 109 -57 66 -108]))))

(deftest base64-test
  (testing "Base64 encoding."
    (is (= (seq (b64/decode (b64/encode (aes/byte-array (range 10)))))
           (range 10)))))


(deftest test-md5
  (is (= (md5/encode "geheimnis")
         "525e92c6aa11544a2ab794f8921ecb0f")))