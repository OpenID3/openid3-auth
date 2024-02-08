#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $SCRIPT_DIR/../indexer

if [ -z "${ENV}" ]; then
    env='dev'
else
    env=${ENV}
fi

doppler run --config $env -- node ./dist/watch.js
