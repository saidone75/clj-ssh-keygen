;; Copyright (c) 2020-2024 Saidone

(ns clj-ssh-keygen.core
  (:import [java.security SecureRandom])
  (:gen-class))

(require '[clj-ssh-keygen.utils :as utils]
         '[clj-ssh-keygen.oid :as oid])

;; (minimum) key length
(def ^:private key-length 2048)

;; public exponent
(def ^:private e (biginteger 65537))

;; generate a prime number of (key length / 2) bits
(defn- genprime [kl]
  (loop [n (BigInteger/probablePrime (quot kl 2) (SecureRandom.))]
    (if-not (= 1 (.mod n e))
      n
      (recur (BigInteger/probablePrime (quot kl 2) (SecureRandom.))))))

;; key as a quintuplet (e, p, q, n, d)
(defn generate-key
  "Generate a PKCS #1 key of a given `kl` length (in bits, default to 2048 if not specified).
  The key is returned as a map meant to be used with [[public-key]], [[openssh-public-key]] or [[private-key]] functions.\\
  See https://www.di-mgt.com.au/rsa_alg.html#keygen for algorithm insights."
  [& [kl]]
  (let [kl (if (< (or kl key-length) key-length) key-length (or kl key-length))
        ;; public exponent
        e e
        ;; secret prime 1
        p (genprime kl)
        ;; secret prime 2
        ;; making sure that p x q (modulus) is exactly "kl" bit long
        q (loop [q (genprime kl)]
            (if (= kl (.bitLength (.multiply p q)))
              q
              (recur (genprime (if (odd? kl) (inc kl) kl)))))
        ;; modulus
        n (.multiply p q)
        ;; private exponent
        d (.modInverse e (.multiply
                           (.subtract p (biginteger 1))
                           (.subtract q (biginteger 1))))]
    {:e e :p p :q q :n n :d d}))

;; ASN.1 encoding stuff
;;
;; the bare minimum for working with PKCS #1 keys
;; http://luca.ntop.org/Teaching/Appunti/asn1.html
;;
;; compute length of ASN.1 content
(defn- asn1-length [c]
  (let [c (count c)]
    (cond
      (< c 128) [(unchecked-byte c)]
      (and (> c 127) (< c 256)) (concat [(unchecked-byte 0x81)] [(unchecked-byte c)])
      :else (concat [(unchecked-byte 0x82)] (.toByteArray (biginteger c))))))

;; ASN.1 generic encoding
(defn- asn1-enc [tag content]
  (byte-array
    (concat
      [(unchecked-byte tag)]
      (asn1-length content)
      content)))

;; ASN.1 encoding for INTEGER
(defn- asn1-int [n]
  (asn1-enc 0x02 (.toByteArray n)))

;; ASN.1 encoding for SEQUENCE
(defn- asn1-seq [n]
  (asn1-enc 0x30 n))

;; ASN.1 encoding for OBJECT
(defn- asn1-obj [n]
  (asn1-enc 0x06 n))

;; ASN.1 encoding for NULL
(defn- asn1-null []
  (concat
    [(unchecked-byte 0x05) (unchecked-byte 0x00)]))

;; ASN.1 encoding for BIT STRING
(defn- asn1-bit-str [n]
  (asn1-enc 0x03 (concat
                   ;; unused bits for padding
                   [(unchecked-byte 0x00)]
                   n)))

;; ASN.1 encoding for OCTET STRING
(defn- asn1-oct-str [n]
  (asn1-enc 0x04 n))

;; PKCS-1 OID value for RSA encryption
;; see https://www.alvestrand.no/objectid/1.2.840.113549.1.1.1.html
(def ^:private pkcs1-oid "1.2.840.113549.1.1.1")

;; RSA public key (only modulus (p x q) and public exponent)
;; https://tools.ietf.org/html/rfc3447#appendix-A.1.1
(defn public-key
  "Return a RSA public key representation of a `key`."
  [key]
  (asn1-seq
    (concat
      (asn1-seq
        (concat
          (asn1-obj
            (map #(unchecked-byte %) (oid/oid-to-bytes pkcs1-oid)))
          (asn1-null)))
      (asn1-bit-str
        (asn1-seq
          (concat
            ;; modulus
            (asn1-int (:n key))
            ;; public exponent
            (asn1-int (:e key))))))))

;; OpenSSH public key (id_rsa.pub) more familiar for ssh users
;; 
;; compute item length as required from OpenSSH
;; 4 bytes format
(defn- openssh-length [c]
  (loop [c (.toByteArray (biginteger (count c)))]
    (if (= 4 (count c))
      c
      (recur (concat [(unchecked-byte 0x00)] c)))))

;; concat item length with item represented as byte array
(defn- openssh-item [i]
  (let [ba
        (cond
          (string? i) (.getBytes i)
          :else (.toByteArray i))]
    (concat
      (openssh-length ba)
      ba)))

;; same information of pem in a slightly different format
(defn openssh-public-key
  "Return an OpenSSH public key representation of a `key`."
  [key]
  (byte-array
    (concat
      ;; string prefix
      (openssh-item "ssh-rsa")
      ;; public exponent
      (openssh-item (:e key))
      ;; modulus
      (openssh-item (:n key)))))

;; RSA private key
;; https://tools.ietf.org/html/rfc3447#appendix-A.1.2
(defn private-key
  "Return a RSA private key representation of a `key`."
  [key]
  (asn1-seq
    (concat
      (asn1-int (biginteger 0))
      (asn1-seq
        (concat
          (asn1-obj
            (map #(unchecked-byte %) (oid/oid-to-bytes pkcs1-oid)))
          (asn1-null)))
      (asn1-oct-str
        (asn1-seq
          (concat
            ;; version
            (asn1-int (biginteger 0))
            ;; modulus
            (asn1-int (:n key))
            ;; public exponent
            (asn1-int (:e key))
            ;; private exponent
            (asn1-int (:d key))
            ;; prime1
            (asn1-int (:p key))
            ;; prime2
            (asn1-int (:q key))
            ;; exponent1
            (asn1-int (.mod (:d key) (.subtract (:p key) (biginteger 1))))
            ;; exponent2
            (asn1-int (.mod (:d key) (.subtract (:q key) (biginteger 1))))
            ;; coefficient
            (asn1-int (.modInverse (:q key) (:p key)))))))))

(defn write-private-key!
  "Get the RSA private key from `k` and write it to a file named `f`."
  [k f]
  (utils/write-private-key! (private-key k) f))

(defn write-public-key!
  "Get the RSA public key from `k` and write it to a file named `f`."
  [k f]
  (utils/write-public-key! (public-key k) f))

(defn write-openssh-public-key!
  "Get the OpenSSH public key from `k` and write it to a file named `f`."
  [k f]
  (utils/write-openssh-public-key! (openssh-public-key k) f))
