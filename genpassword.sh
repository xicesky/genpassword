#!/bin/bash

WANTED_LEN=8
WANTED_CHARS="_A-Za-z0-9!?#.="

[ -z "$1" ] || WANTED_LEN="$1"
[ -z "$2" ] || WANTED_CHARS="$2"

echo "Generating password of length $WANTED_LEN from /dev/random..."
echo "Wanted characters are: $WANTED_CHARS"
echo -n "Please wait: "

PW=""
LEN=0
while (( LEN < WANTED_LEN )) ; do
	CHAR=`head -c 1 /dev/random | tr -dc "$WANTED_CHARS"`
	PW="$PW$CHAR"
	LEN=${#PW}
	#head -c $PWDLEN /dev/random | tr -dc "$WANTED"
	#echo -n "."
	echo -n "$CHAR"
done
echo " done"
echo "Here is your new password:"
echo ""
echo "$PW"

