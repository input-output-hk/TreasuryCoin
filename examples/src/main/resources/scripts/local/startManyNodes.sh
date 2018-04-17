#!/bin/bash

if [ -z "$1" ]
  then
    echo "No argument supplied"
    exit
fi
echo "Starting "$1" nodes ..."

gnome-terminal -e "java -jar ../../../../../target/scala-2.12/TreasuryCoin.jar ../../settings.conf"

for i in `seq 2 $1`;
do
    gnome-terminal -e "java -jar ../../../../../target/scala-2.12/TreasuryCoin.jar ../../settings$i.conf"
done 