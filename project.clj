(defproject clj-ssh-keygen "0.1.0-SNAPSHOT"
  :description "Genereate RSA PKCS #1 key-pairs from scratch in Clojure"
  :url "http://saidone.org"
  :license {:name "MIT"
            :url "https://github.com/saidone75/clj-ssh-keygen/blob/master/LICENSE"}
  :dependencies [[org.clojure/clojure "1.10.1"]]
  :main ^:skip-aot clj-ssh-keygen.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
