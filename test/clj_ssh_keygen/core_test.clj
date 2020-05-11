(ns clj-ssh-keygen.core-test
  (:require [clojure.test :refer :all]
            [clj-ssh-keygen.core :refer :all]))

(deftest keygen
  (let [key (generate-key)]
    (write-private-key! (private-key key) "pvt.pem")
    (write-public-key! (public-key key) "pub.pem")
    (write-openssh-public-key! (openssh-public-key key) "id_rsa.pub")))
