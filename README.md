# clj-ssh-keygen

Genereate RSA PKCS #1 key-pairs **from scratch** in Clojure

## Usage

```(let [kp (generate-key-pair)]
    (utils/write-private-key! (private-key kp) "pvt.pem")
    (utils/write-public-key! (public-key kp) "pub.pem")
    (utils/write-openssh-public-key! (openssh-public-key kp) "id_rsa.pub"))```
