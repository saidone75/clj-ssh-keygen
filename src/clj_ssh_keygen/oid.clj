;; Copyright (c) 2020-2024 Saidone

(ns clj-ssh-keygen.oid
  (:gen-class))

(require '[clojure.string :as str])

(defn- token-to-bytes [token]
  (let [bitlist
        (partition-all
          7
          ;; prepend zeros to match multiple of 7 length
          (concat (repeat (- 7 (rem (count (Integer/toString token 2)) 7)) \0)
                  (Integer/toString token 2)))]
    (concat
      (map
        #(Integer/valueOf (apply str (cons \1 %)) 2)
        (butlast bitlist))
      (list (Integer/valueOf (apply str (cons \0 (last bitlist))) 2)))))

;; https://stackoverflow.com/questions/3376357/how-to-convert-object-identifiers-to-hex-strings
(defn oid-string-to-bytes [oid]
  (let [tokens (map #(Integer/parseInt %) (str/split oid #"\."))]
    (flatten
      (concat
        ;; first two tokens encoded separately
        (list (+ (* 40 (first tokens)) (second tokens)))
        (map
          token-to-bytes
          (drop 2 tokens))))))
