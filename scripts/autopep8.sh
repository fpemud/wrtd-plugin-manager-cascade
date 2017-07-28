#!/bin/bash

LIBFILES="$(find ./wvpn_n2n -name '*.py' | tr '\n' ' ')"

autopep8 -ia --ignore=E501 ${LIBFILES}
