#!/bin/bash

if [ -z "${ENV}" ]; then
    env='dev'
else
    env=${ENV}
fi

doppler run --config $env -- node ./dist/watch.js
