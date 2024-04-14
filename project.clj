(defproject clj-ssh-keygen "0.2.4"
  :description "Generate RSA PKCS #1 key-pairs from scratch in Clojure"
  :url "https://github.com/saidone75/clj-ssh-keygen"
  :license {:name "MIT"
            :url "https://github.com/saidone75/clj-ssh-keygen/blob/master/LICENSE"}
  :dependencies [[org.clojure/clojure "1.11.2"]]
  :main ^:skip-aot clj-ssh-keygen.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
