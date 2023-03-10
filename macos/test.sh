#!/bin/bash

current_dir=$(basename `pwd`)
if [ $current_dir == 'macos' ]; then
    cd ..
fi

source macos/.env

docker run --rm -ti --user "$(id -u)":"$(id -g)" -v "$(pwd):/app"  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder ./macos/__run_tests.sh
