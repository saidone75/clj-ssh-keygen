#!/bin/bash

sudo rm -rf ./tmp/cljdoc
mkdir -p ./tmp/cljdoc

lein install

docker run --rm \
  --volume $(pwd):/clj-ssh-keygen \
  --volume "$HOME/.m2:/root/.m2" \
  --volume ./tmp/cljdoc:/app/data \
  --entrypoint clojure \
  cljdoc/cljdoc -Sforce -M:cli ingest \
    --project clj-ssh-keygen/clj-ssh-keygen \
    --version 0.2.4-SNAPSHOT \
    --git /clj-ssh-keygen \

docker run --rm -p 8000:8000 -v ./tmp/cljdoc:/app/data --volume "$HOME/.m2:/root/.m2" cljdoc/cljdoc
