#!/bin/bash

current_dir=$(basename `pwd`)
if [ $current_dir == 'macos' ]; then
    cd ..
fi

source macos/.env

test=''
while getopts 'rt:' OPTION; do
  case "$OPTION" in
    t)
      test=$OPTARG
      ;;
  esac
done
shift "$(($OPTIND -1))"

if [ -z $test ]; then
    docker run --rm -ti --user "$(id -u)":"$(id -g)" -v "$(pwd):/app" $DEV_TOOL_IMAGE ./macos/__run_tests.sh
else
    docker run --rm -ti --user "$(id -u)":"$(id -g)" -v "$(pwd):/app" $DEV_TOOL_IMAGE ./unit-tests/build/$test
fi
