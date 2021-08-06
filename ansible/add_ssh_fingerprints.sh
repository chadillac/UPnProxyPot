#!/usr/bin/env bash

ips=$(cat inventory.yaml | grep root | awk '{print $1}')

for ip in $ips; do
   ssh-keyscan -H $ip >> ~/.ssh/known_hosts
done
