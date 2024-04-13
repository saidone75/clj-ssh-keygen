# clj-ssh-keygen

[![Clojars Project](https://img.shields.io/clojars/v/clj-ssh-keygen.svg)](https://clojars.org/clj-ssh-keygen)

Generate RSA PKCS #1 keys **from scratch** and **without 3rd party libs** in Clojure, export **PEM** and **OpenSSH** formats

*☛ intended for hacking and educational purposes only!*

![public key](https://i.postimg.cc/HLhvSkpk/pubkey.png)

## Usage
```clojure
 (let [key (generate-key)]
    (write-private-key! key "pvt.pem")
    (write-public-key! key "pub.pem")
    (write-openssh-public-key! key "id_rsa.pub")))
```
for generating a default (2048 bit) length key, while:
```clojure
(write-private-key! (generate-key 2345) "pvt.pem")
```
will issue a custom length key:
```console
$ openssl rsa -noout -text -in pvt.pem|head -n 1
RSA Private-Key: (2345 bit, 2 primes)
```

## License
Copyright (c) 2020-2024 Saidone

Distributed under the MIT License
