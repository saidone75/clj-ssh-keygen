(ns clj-ssh-keygen.oid
  (:gen-class))

(require '[clojure.string :as str])

(defn- token-to-byte [token]
  (let [bitlist
        (partition-all
         7
         (concat (repeat (- 7 (rem (count (Integer/toString token 2)) 7)) \0)
                 (Integer/toString token 2)))]
    (concat
     (map
      #(Integer/valueOf (apply str (cons \1 %)) 2)
      (butlast bitlist))
     (list (Integer/valueOf (apply str (cons \0 (last bitlist))) 2)))))

;; https://stackoverflow.com/questions/3376357/how-to-convert-object-identifiers-to-hex-strings
(defn oid-string-to-hex [oid]
  (let [tokens (map #(Integer/parseInt %) (str/split oid #"\."))]
    (flatten
     (concat
      (list (+ (* 40 (first tokens)) (second tokens)))
      (map
       token-to-byte
       (drop 2 tokens))))))
