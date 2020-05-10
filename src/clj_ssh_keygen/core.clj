(ns clj-ssh-keygen.core
  (:import [java.security SecureRandom]) 
  (:gen-class))

(require '[clj-ssh-keygen.utils :as utils])

;; key length
(def key-length 2048)

;; generate a prime number of (key lenght / 2) bits
(defn- genprime [e key-length]
  (loop [n (BigInteger/probablePrime (/ key-length 2) (SecureRandom.))]
    (if (not (= 1 (.mod n e)))
      n
      (recur (BigInteger/probablePrime (/ key-length 2) (SecureRandom.))))))

;; key pair as a quintuple (e, p, q, n, d)
(defn generate-key-pair []
  (let [;; public exponent
        e (BigInteger/valueOf 65537) 
        ;; secret prime 1
        p (genprime e key-length)
        ;; secret prime 2
        ;; making sure that p x q (modulus) is exactly "key-length" bit long
        q (loop [q (genprime e key-length)]
            (if (= key-length (.bitLength (.multiply p q)))
              q
              (recur (genprime e key-length))))
        ;; modulus
        n (.multiply p q)
        ;; private exponent
        d (.modInverse e (.multiply
                          (.subtract p BigInteger/ONE)
                          (.subtract q BigInteger/ONE)))]
    {:e e :p p :q q :n n :d d}))

(defn- asn1-int [n]
  (let [n (.toByteArray n)]
    (byte-array
     (concat
      [(byte 2)]
      (cond
        (< (count n) 128) [(unchecked-byte (count n))]
        (and (> (count n) 127) (< (count n) 256)) (concat [(unchecked-byte 0x81)] [(unchecked-byte (count n))])
        :else (concat [(unchecked-byte 0x82)] (.toByteArray (BigInteger/valueOf (count n)))))
      n))))

(defn- asn1-seq [n]
  (byte-array
   (concat
    [(unchecked-byte 0x30)]
    (cond
      (< (count n) 128) [(unchecked-byte (count n))]
      (and (> (count n) 127) (< (count n) 256)) (concat [(unchecked-byte 0x81)] [(unchecked-byte (count n))])
      :else (concat [(unchecked-byte 0x82)] (.toByteArray (BigInteger/valueOf (count n)))))
    n)))

(defn- asn1-obj [n]
  (concat
   [(byte 0x06)]
   (.toByteArray (BigInteger/valueOf (count n)))
   n))

(defn- asn1-null [n]
  (concat
   [(byte 0x05)]
   (.toByteArray (BigInteger/valueOf (count n)))))

(defn- asn1-bit-str [n]
  (concat
   [(byte 0x03)]
   (cond
     (< (count n) 128) nil
     (and (> (count n) 127) (< (count n) 256)) [(unchecked-byte 0x81)]
     :else [(unchecked-byte 0x82)])
   (.toByteArray (BigInteger/valueOf (inc (count n))))
   [(byte 0x00)] ;; investigate why this is needed
   n))

(defn- asn1-oct-str [n]
  (concat
   [(byte 0x04)]
   (cond
     (< (count n) 128) nil
     (and (> (count n) 127) (< (count n) 256)) [(unchecked-byte 0x81)]
     :else [(unchecked-byte 0x82)])
   (.toByteArray (BigInteger/valueOf (count n)))
   n))

(def pkcs1-oid-value [1 2 840 113549 1 1 1])
(def pkcs1-oid-value-hex [0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x01 0x01])

(defn public-key [kp]
  (asn1-seq
   (concat
    (asn1-seq
     (concat
      (asn1-obj
       (map #(unchecked-byte %) pkcs1-oid-value-hex))
      (asn1-null nil)))
    (asn1-bit-str 
     (asn1-seq
      (concat
       ;; modulus
       (asn1-int (:n kp))
       ;; public exponent
       (asn1-int (:e kp))))))))

;; 4 bytes length + "ssh-rsa" string
(def ssh-prefix [0x00 0x00 0x00 0x07 0x73 0x73 0x68 0x2d 0x72 0x73 0x61])

;; lenght of e (3 bytes)
(def ssh-exponent-length [0x00 0x00 0x00 0x03])

;; more familiar for ssh users
;; same informations of pem in a sligthly different format
(defn openssh-public-key [kp]
  (byte-array
   (concat
    (map #(unchecked-byte %) ssh-prefix)
    (map #(unchecked-byte %) ssh-exponent-length)
    (.toByteArray (:e kp))
    (map #(unchecked-byte %) [0 0])
    (.toByteArray (BigInteger/valueOf (count (.toByteArray (:n kp)))))
    (.toByteArray (:n kp)))))

(defn private-key [kp]
  (asn1-seq
   (concat
    (asn1-int BigInteger/ZERO)
    (asn1-seq
     (concat
      (asn1-obj
       (map #(unchecked-byte %) pkcs1-oid-value-hex))
      (asn1-null nil)))
    (asn1-oct-str
     (asn1-seq
      (concat
       ;; version
       (asn1-int BigInteger/ZERO)
       ;; modulus
       (asn1-int (:n kp))
       ;; public exponent
       (asn1-int (:e kp))
       ;; private exponent
       (asn1-int (:d kp))
       ;; prime1
       (asn1-int (:p kp))
       ;; prime2
       (asn1-int (:q kp))
       ;; exponent1
       (asn1-int (.mod (:d kp) (.subtract (:p kp) BigInteger/ONE)))
       ;; exponent2
       (asn1-int (.mod (:d kp) (.subtract (:q kp) BigInteger/ONE)))
       ;; coefficient
       (asn1-int (.modInverse (:q kp) (:p kp)))))))))

(defn -main
  [& args]
  (let [kp (generate-key-pair)]
    (utils/write-private-key! (private-key kp) "pvt.pem")
    (utils/write-public-key! (public-key kp) "pub.pem")
    (utils/write-openssh-public-key! (openssh-public-key kp) "id_rsa.pub")))

;; show public key
;; openssl rsa -noout -text -pubin -inform PEM -in pub.pem

;; extract public key from private
;; openssl rsa -pubout -in pvt.pem -out pub.pem

;; openssh -i pvt.pem user@host
