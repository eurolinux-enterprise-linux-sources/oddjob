#!/bin/sh
env | grep '^ODDJOB' | sed -e s,=,=\",g -e s,\$,\",g | sort -d
exit 0
