;; Copyright (c) 2020 Saidone

(ns clj-ssh-keygen.core
  (:import [java.security SecureRandom]) 
  (:gen-class))

(require '[clj-ssh-keygen.utils :as utils])

;; key length
(def key-length 2048)

;; public exponent
(def e (BigInteger/valueOf 65537))

;; generate a prime number of (key lenght / 2) bits
(defn- genprime []
  (loop [n (BigInteger/probablePrime (/ key-length 2) (SecureRandom.))]
    (if (not (= 1 (.mod n e)))
      n
      (recur (BigInteger/probablePrime (/ key-length 2) (SecureRandom.))))))

;; key as a quintuplet (e, p, q, n, d)
;; see https://www.di-mgt.com.au/rsa_alg.html#keygen for algorithm insights
(defn generate-key []
  (let [;; public exponent
        e e
        ;; secret prime 1
        p (genprime)
        ;; secret prime 2
        ;; making sure that p x q (modulus) is exactly "key-length" bit long
        q (loop [q (genprime)]
            (if (= key-length (.bitLength (.multiply p q)))
              q
              (recur (genprime))))
        ;; modulus
        n (.multiply p q)
        ;; private exponent
        d (.modInverse e (.multiply
                          (.subtract p BigInteger/ONE)
                          (.subtract q BigInteger/ONE)))]
    {:e e :p p :q q :n n :d d}))

;; ASN.1 encoding stuff
;;
;; the bare minimum for working with PKCS #1 keys
;; http://luca.ntop.org/Teaching/Appunti/asn1.html
;;
;; compute length of ASN.1 content
(defn- asn1-length [c]
  (cond
    (< (count c) 128)[(unchecked-byte (count c))]
    (and (> (count c) 127) (< (count c) 256)) (concat [(unchecked-byte 0x81)] [(unchecked-byte (count c))])
    :else (concat [(unchecked-byte 0x82)] (.toByteArray (BigInteger/valueOf (count c))))))

;; ASN.1 generic encoding
(defn- asn1-enc [tag content & [ub]]
  (byte-array
   (concat
    [(unchecked-byte tag)]
    (asn1-length (if (nil? ub)
                   content
                   (byte-array (concat [(unchecked-byte 0x00)] content))))
    ;; unused bits for BIT STRING
    (if (not (nil? ub)) [(unchecked-byte ub)])
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
  (asn1-enc 0x03 n 0x00))

;; ASN.1 encoding for OCTET STRING
(defn- asn1-oct-str [n]
  (asn1-enc 0x04 n))

;; PKCS-1 OID value for RSA encryption
;; see https://www.alvestrand.no/objectid/1.2.840.113549.1.1.1.html
(def pkcs1-oid-value [1 2 840 113549 1 1 1])

;; byte encoding for the above
;; coded "by hand" because of the "odd" encoding logic
;; https://stackoverflow.com/questions/3376357/how-to-convert-object-identifiers-to-hex-strings
(def pkcs1-oid-value-hex [0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x01 0x01])

;; RSA public key (only modulus (p x q) and public exponent)
;; https://tools.ietf.org/html/rfc3447#appendix-A.1.1
(defn public-key [kp]
  (asn1-seq
   (concat
    (asn1-seq
     (concat
      (asn1-obj
       (map #(unchecked-byte %) pkcs1-oid-value-hex))
      (asn1-null)))
    (asn1-bit-str 
     (asn1-seq
      (concat
       ;; modulus
       (asn1-int (:n kp))
       ;; public exponent
       (asn1-int (:e kp))))))))

;; OpenSSH pubic key (id_rsa.pub) more familiar for ssh users
;;
;; prefix and exponent length hardcoded
;; 4 bytes prefix length + "ssh-rsa" string (7 bytes)
(def ssh-prefix [0x00 0x00 0x00 0x07 0x73 0x73 0x68 0x2d 0x72 0x73 0x61])

;; 4 bytes lenght for e (3 bytes)
(def ssh-exponent-length [0x00 0x00 0x00 0x03])

;; same informations of pem in a sligthly different format
(defn openssh-public-key [kp]
  (byte-array
   (concat
    (map #(unchecked-byte %) ssh-prefix)
    (map #(unchecked-byte %) ssh-exponent-length)
    ;; public exponent
    (.toByteArray (:e kp))
    (map #(unchecked-byte %) [0x00 0x00])
    (.toByteArray (BigInteger/valueOf (count (.toByteArray (:n kp)))))
    ;; modulus
    (.toByteArray (:n kp)))))

;; RSA private key
;; https://tools.ietf.org/html/rfc3447#appendix-A.1.2
(defn private-key [kp]
  (asn1-seq
   (concat
    (asn1-int BigInteger/ZERO)
    (asn1-seq
     (concat
      (asn1-obj
       (map #(unchecked-byte %) pkcs1-oid-value-hex))
      (asn1-null)))
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

(defn write-private-key! [k f]
  (utils/write-private-key! k f))

(defn write-public-key! [k f]
  (utils/write-public-key! k f))

(defn write-openssh-public-key! [k f]
  (utils/write-openssh-public-key! k f))

(defn -main
  [& args]
  (let [key (generate-key)]
    (write-private-key! (private-key key) "pvt.pem")
    (write-public-key! (public-key key) "pub.pem")
    (write-openssh-public-key! (openssh-public-key key) "id_rsa.pub")))

;; Test keys integrity with openssl
;;
;; show public key
;; $ openssl rsa -noout -text -pubin -inform PEM -in pub.pem
;;
;; extract public key from private
;; $ openssl rsa -pubout -in pvt.pem -out pub.pem
;;
;; use key to authenticate on a host
;; id_rsa.pub must be appended to ~/.ssh/authorized_keys for user on destination host
;; https://man.openbsd.org/ssh#AUTHENTICATION
;; $ ssh -i pvt.pem user@host
;;
;; awesome online tool for debugging ASN.1 https://lapo.it/asn1js/
