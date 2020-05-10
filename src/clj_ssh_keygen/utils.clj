(ns clj-ssh-keygen.utils
  (:import [java.util Base64]) 
  (:gen-class))

(defn- wrap-72 [s]
  (reduce
   #(str %1 %2 "\n")
   ""
   (map
    #(apply str %)
    (partition-all 72 s))))

(defn write-public-key! [k f]
  (spit f
        (str
         "-----BEGIN PUBLIC KEY-----\n"
         (wrap-72
          (.encodeToString (Base64/getEncoder) k))
         "-----END PUBLIC KEY-----\n")))

(defn write-private-key! [k f]
  (spit f
        (str
         "-----BEGIN PRIVATE KEY-----\n"
         (wrap-72
          (.encodeToString (Base64/getEncoder) k))
         "-----END PRIVATE KEY-----\n")))

(defn write-openssh-public-key! [k f]
  (spit f
        (str
         "ssh-rsa "
         (.encodeToString (Base64/getEncoder) k))))
