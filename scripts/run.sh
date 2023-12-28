#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pm2 start $SCRIPT_DIR/server.sh

pm2 start $SCRIPT_DIR/watch.sh

cd $SCRIPT_DIR/../functions

echo "installing dependencies"
pnpm i

npm run build && npm run serve
