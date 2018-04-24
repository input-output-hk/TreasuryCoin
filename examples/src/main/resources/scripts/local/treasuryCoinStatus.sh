#!/usr/bin/env bash

my_dir="$(dirname "$0")"
source "$my_dir/restAPIips.sh"

for ip in "${allIps[@]}"
do
   echo "$ip"
   curl -s -X GET --header 'Accept: application/json' 'http://'$ip'/debug/info' | grep height
done