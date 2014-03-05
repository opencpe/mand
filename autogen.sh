#!/bin/sh

libtoolize -f -c
shtoolize -q all
aclocal
autoheader
automake --add-missing
autoconf
