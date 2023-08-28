#!/bin/bash

current_dir=$(basename `pwd`)
if [ $current_dir == 'macos' ]; then
    cd ..
fi

source macos/.env

clean=''
while getopts ':c:' OPTION; do
  case "$OPTION" in
    c)
      clean=$OPTARG
      ;;
  esac
done
shift "$(($OPTIND -1))"

if [ -z $clean ]; then
    docker run --rm -ti --user "$(id -u)":"$(id -g)" -v "$(pwd):/app" $DEV_TOOL_IMAGE make clean
fi

docker run --rm -ti --user "$(id -u)":"$(id -g)" -v "$(pwd):/app" $DEV_TOOL_IMAGE make
