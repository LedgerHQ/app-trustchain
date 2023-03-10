#!/bin/bash
cd unit-tests
CTEST_OUTPUT_ON_FAILURE=1 make -C build test