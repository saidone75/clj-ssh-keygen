;; Copyright (c) 2020-2024 Saidone

(ns clj-ssh-keygen.utils
  (:import [java.util Base64])
  (:gen-class))

;; wrap string to 72 characters
(defn- wrap-72 [s]
  (reduce
    #(str %1 %2 "\n")
    ""
    (map
      #(apply str %)
      (partition-all 72 s))))

;; write public key base64 encoded
(defn write-public-key! [k f]
  (spit f
        (str
          "-----BEGIN PUBLIC KEY-----\n"
          (wrap-72
            (.encodeToString (Base64/getEncoder) k))
          "-----END PUBLIC KEY-----\n")))

;; write private key base64 encoded
(defn write-private-key! [k f]
  (spit f
        (str
          "-----BEGIN PRIVATE KEY-----\n"
          (wrap-72
            (.encodeToString (Base64/getEncoder) k))
          "-----END PRIVATE KEY-----\n")))

;; write openssh public key base64 encoded
(defn write-openssh-public-key! [k f]
  (spit f
        (str
          "ssh-rsa "
          (.encodeToString (Base64/getEncoder) k))))
