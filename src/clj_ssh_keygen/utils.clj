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

(defn write-public-key!
  "Encode a RSA public key `k` to base64, wrap to 72 characters and write it to a file named `f`."
  [k f]
  (spit f
        (str
          "-----BEGIN PUBLIC KEY-----\n"
          (wrap-72
            (.encodeToString (Base64/getEncoder) k))
          "-----END PUBLIC KEY-----\n")))

(defn write-private-key!
  "Encode a RSA private key `k` to base64, wrap to 72 characters and write it to a file named `f`."
  [k f]
  (spit f
        (str
          "-----BEGIN PRIVATE KEY-----\n"
          (wrap-72
            (.encodeToString (Base64/getEncoder) k))
          "-----END PRIVATE KEY-----\n")))

(defn write-openssh-public-key!
  "Encode an OpenSSH public key `k` to base64 and write it to a file named `f`."
  [k f]
  (spit f
        (str
          "ssh-rsa "
          (.encodeToString (Base64/getEncoder) k))))