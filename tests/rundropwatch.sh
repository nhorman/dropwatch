#!/bin/sh

echo -e "set alertlimit 1\nstart\nstop" | ../src/dropwatch -l kas

