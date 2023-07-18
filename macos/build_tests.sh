#!/bin/bash
set -e

current_dir=$(basename `pwd`)
if [ $current_dir == 'macos' ]; then
    cd ..
fi

source macos/.env

run=false
while getopts 'r' OPTION; do
  case "$OPTION" in
    r)
      run=true
      ;;
  esac
done
shift "$(($OPTIND -1))"

docker run --rm -ti --user "$(id -u)":"$(id -g)" -v "$(pwd):/app"  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder "./macos/__build_tests.sh"

if [[ $run == true ]]; then
    ./macos/test.sh
fi