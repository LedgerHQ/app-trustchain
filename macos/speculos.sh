#!/bin/bash

current_dir=$(basename `pwd`)
if [ $current_dir == 'macos' ]; then
    cd ..
fi

source macos/.env

docker run --privileged -ti -p 5000:5000 -v "$(pwd):/app" --platform linux/amd64 ghcr.io/ledgerhq/speculos:$SPECULOS_VERSION /app/bin/app.elf -m nanos --display headless