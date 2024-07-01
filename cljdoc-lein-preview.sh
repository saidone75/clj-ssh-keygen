#!/bin/bash

# get project name
PROJECT=$(cat project.clj | grep defproject | cut -d " " -f 2 | cut -d "/" -f 2)
# get group id
GROUP_ID=$(cat project.clj | grep defproject | cut -d " " -f 2 | cut -d "/" -f 1)
# get version
VERSION=$(cat project.clj | grep defproject | cut -d " " -f 3 | tr -d '"')

echo "Generating cljdoc for $PROJECT-$VERSION"

# clean up previous run
sudo rm -rf /tmp/cljdoc
mkdir -p /tmp/cljdoc

# build and install into local repo
echo "Installing $PROJECT-$VERSION jar and pom into local repo"
lein install

# ingest into cljdoc
docker run --rm \
  -v $(pwd):/$PROJECT \
  -v $HOME/.m2:/root/.m2 \
  -v /tmp/cljdoc:/app/data \
  --entrypoint clojure \
  cljdoc/cljdoc -Sforce -M:cli ingest \
    --project $GROUP_ID/$PROJECT \
    --version $VERSION \
    --git /$PROJECT \

# start server
docker run --rm -p 8000:8000 -v /tmp/cljdoc:/app/data -v $HOME/.m2:/root/.m2 cljdoc/cljdoc
