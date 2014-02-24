#!/bin/sh

libtoolize -f -c
shtoolize -q all
aclocal
automake
autoconf
