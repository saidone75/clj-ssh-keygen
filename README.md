# clj-ssh-keygen

Generate RSA PKCS #1 keys **from scratch** (without 3rd party libs) in Clojure, export **PEM** and **OpenSSH** formats

*☛ intended for hacking and educational purposes only!*

![public key](https://i.postimg.cc/g2hqR9xz/pubkey.png "public key")

## Usage
```clojure
 (let [key (generate-key)]
    (write-private-key! (private-key key) "pvt.pem")
    (write-public-key! (public-key key) "pub.pem")
    (write-openssh-public-key! (openssh-public-key key) "id_rsa.pub")))
```

## License
Copyright (c) 2020 Saidone

Distributed under the MIT License
