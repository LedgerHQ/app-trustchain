#!/bin/bash
set -e

current_dir=$(basename `pwd`)
if [ $current_dir == 'macos' ]; then
    cd ..
fi

source macos/.env

run=false
test=''

while getopts 'rt:' OPTION; do
  case "$OPTION" in
    r)
      run=true
      ;;
    t)
      test=$OPTARG
      ;;
  esac
done
shift "$(($OPTIND -1))"

docker run --rm -ti --user "$(id -u)":"$(id -g)" -v "$(pwd):/app" $DEV_TOOL_IMAGE "./macos/__build_tests.sh"

if [[ $run == true ]]; then
    ./macos/test.sh
fi

[ -z "$test" ] || docker run --rm -ti --user "$(id -u)":"$(id -g)" -v "$(pwd):/app" $DEV_TOOL_IMAGE "./unit-tests/build/$test"
