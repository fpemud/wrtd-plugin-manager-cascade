#!/bin/bash

LIBFILES="$(find ./manager_cascade -name '*.py' | tr '\n' ' ')"

autopep8 -ia --ignore=E501 ${LIBFILES}
