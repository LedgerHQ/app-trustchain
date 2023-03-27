#!/bin/bash

current_dir=$(basename `pwd`)
if [ $current_dir == 'macos' ]; then
    cd ..
fi

pk=true

if test -f "./macos/.custom_ca"; then
    source macos/.custom_ca
    python3 -m ledgerblue.setupCustomCA --targetId 0x31100004 --public $SCP_PUBKEY --name dev
fi

python3 -m ledgerblue.genCAPair | grep -Eo "[0-9a-f]{64,200}" | while read line 
do
    if [ $pk = true ]; then
        echo "SCP_PUBKEY=$line" > macos/.custom_ca
        pk=false
    else
        echo "SCP_PRIVKEY=$line" >> macos/.custom_ca
    fi
done
source macos/.custom_ca
python3 -m ledgerblue.setupCustomCA --targetId 0x31100004 --public $SCP_PUBKEY --name dev