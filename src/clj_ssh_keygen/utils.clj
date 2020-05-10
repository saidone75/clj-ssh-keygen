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

(defn write-public-key! [n]
  (spit "./pub.pem"
        (str
         "-----BEGIN PUBLIC KEY-----\n"
         (wrap-72
          (.encodeToString (Base64/getEncoder) n))
         "-----END PUBLIC KEY-----\n")))

(defn write-private-key! [n]
  (spit "./pvt.pem"
        (str
         "-----BEGIN PRIVATE KEY-----\n"
         (wrap-72
          (.encodeToString (Base64/getEncoder) n))
         "-----END PRIVATE KEY-----\n")))

(defn write-openssh-public-key! [n]
  (spit "./id_rsa.pub"
        (str
         "ssh-rsa "
         (.encodeToString (Base64/getEncoder) n))))
