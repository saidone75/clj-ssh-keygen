(ns clj-ssh-keygen.core
  (:import [java.security SecureRandom]) 
  (:gen-class))

(require '[clj-ssh-keygen.utils :as utils])

;; key length
(def key-length 2048)

;; public exponent
(def e (BigInteger/valueOf 65537))

;; generate a prime number of (key lenght / 2) bits
(defn- genprime [e key-length]
  (loop [n (BigInteger/probablePrime (/ key-length 2) (SecureRandom.))]
    (if (not (= 1 (.mod n e)))
      n
      (recur (BigInteger/probablePrime (/ key-length 2) (SecureRandom.))))))

;; prime1
(def p (genprime e key-length))

;; prime2
;; making sure that p x q (modulus) is 2048 bit long
(def q
  (loop [q (genprime e key-length)]
    (if (= 2048 (.bitLength (.multiply p q)))
      q
      (recur (genprime e key-length)))))

;; modulus
(def n (.multiply p q))

(def l (.multiply (.subtract p BigInteger/ONE) (.subtract q BigInteger/ONE)))

;; private exponent
(def d (.modInverse e l))

(defn- ubyte->byte [b]
  (if (>= b 128)
    (byte (- b 256))
    (byte b)))

(defn- asn1-int [n]
  (let [n (.toByteArray n)]
    (byte-array
     (concat
      [(byte 2)]
      (cond
        (< (count n) 128) [(unchecked-byte (count n))]
        (and (> (count n) 127) (< (count n) 256)) (concat [(byte (ubyte->byte 0x81))] [(unchecked-byte (count n))])
        :else (concat [(byte (ubyte->byte 0x82))] (.toByteArray (BigInteger/valueOf (count n)))))
      n))))

(defn- asn1-seq [n]
  (byte-array
   (concat
    [(byte (ubyte->byte 0x30))]
    (cond
      (< (count n) 128) [(unchecked-byte (count n))]
      (and (> (count n) 127) (< (count n) 256)) (concat [(byte (ubyte->byte 0x81))] [(unchecked-byte (count n))])
      :else (concat [(byte (ubyte->byte 0x82))] (.toByteArray (BigInteger/valueOf (count n)))))
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
     (and (> (count n) 127) (< (count n) 256)) [(byte (ubyte->byte 0x81))]
     :else [(byte (ubyte->byte 0x82))])
   (.toByteArray (BigInteger/valueOf (inc (count n))))
   [(byte 0x00)] ;; investigate why this is needed
   n))

(defn- asn1-oct-str [n]
  (concat
   [(byte 0x04)]
   (cond
     (< (count n) 128) nil
     (and (> (count n) 127) (< (count n) 256)) [(byte (ubyte->byte 0x81))]
     :else [(byte (ubyte->byte 0x82))])
   (.toByteArray (BigInteger/valueOf (count n)))
   n))

(def pkcs1-oid-value [1 2 840 113549 1 1 1])
(def pkcs1-oid-value-hex [0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x01 0x01])

(def public-key
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
      (asn1-int n)
      ;; public exponent
      (asn1-int e)))))))

;; 4 bytes length + "ssh-rsa" string
(def ssh-prefix [0x00 0x00 0x00 0x07 0x73 0x73 0x68 0x2d 0x72 0x73 0x61])

;; lenght of e (3 bytes)
(def ssh-exponent-length [0x00 0x00 0x00 0x03])

;; more familiar for ssh users
;; same informations of pem in a sligthly different format
(def openssh-public-key
 (byte-array
  (concat
   (map #(unchecked-byte %) ssh-prefix)
   (map #(unchecked-byte %) ssh-exponent-length)
   (.toByteArray e)
   (map #(unchecked-byte %) [0 0])
   (.toByteArray (BigInteger/valueOf (count (.toByteArray n))))
   (.toByteArray n))))

(def private-key
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
      (asn1-int n)
      ;; public exponent
      (asn1-int e)
      ;; private exponent
      (asn1-int d)
      ;; prime1
      (asn1-int p)
      ;; prime2
      (asn1-int q)
      ;; exponent1
      (asn1-int (.mod d (.subtract p BigInteger/ONE)))
      ;; exponent2
      (asn1-int (.mod d (.subtract q BigInteger/ONE)))
      ;; coefficient
      (asn1-int (.modInverse q p))))))))

(defn -main
  [& args]
  (utils/write-private-key! private-key)
  (utils/write-public-key! public-key)
  (utils/write-openssh-public-key! openssh-public-key))

;; show public key
;; openssl rsa -noout -text -pubin -inform PEM -in pub.pem

;; extract public key from private
;; openssl rsa -pubout -in pvt.pem -out pub.pem

;; openssh -i pvt.pem user@host
