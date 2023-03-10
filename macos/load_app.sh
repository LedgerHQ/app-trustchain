#!/bin/bash

current_dir=$(basename `pwd`)
if [ $current_dir == 'macos' ]; then
    cd ..
fi

#export `cat .env | xargs`
source macos/.env

python3 -m ledgerblue.loadApp --curve  secp256k1 --appFlags 0x000 --path "44'" --tlv --targetId $TARGET_ID --targetVersion="$TARGET_VERSION" --delete --fileName bin/app.hex --appName $APPNAME --appVersion $APPVERSION --dataSize $((0x`cat debug/app.map |grep _envram_data | tr -s ' ' | cut -f2 -d' '|cut -f2 -d'x'` - 0x`cat debug/app.map |grep _nvram_data | tr -s ' ' | cut -f2 -d' '|cut -f2 -d'x'`)) `ICONHEX=$ICONHEX_VALUE ; [ ! -z "$ICONHEX" ] && echo "--icon $ICONHEX"`
