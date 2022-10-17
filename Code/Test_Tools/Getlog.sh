#!/bin/bash
flag=0
while (( $flag <= 600 ))
do
    let "flag++"
	sudo dmesg > ../log.txt
    sleep 1
done
echo "yes!"
