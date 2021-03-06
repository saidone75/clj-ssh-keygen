(ns clj-ssh-keygen.core-test
  (:require [clojure.test :refer [deftest]]
            [clj-ssh-keygen.core :as core]))

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

(deftest keygen
  (let [key (core/generate-key)]
    (core/write-private-key! key "pvt.pem")
    (core/write-public-key! key "pub.pem")
    (core/write-openssh-public-key! key "id_rsa.pub")))
