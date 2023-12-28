#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $SCRIPT_DIR/../wellknown

pm2 start $SCRIPT_DIR/server.sh

pm2 start $SCRIPT_DIR/watch.sh

cd $SCRIPT_DIR/../functions

npm run serve