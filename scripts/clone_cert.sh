#!/usr/bin/env bash

## create a self signed certificate that mirrors the subject line of another TLS cert

key_path=./keys

## get the subject line from the remote server (proxy endpoint)
subj_master=$(curl -kv --resolve $2:443:$1 https://$2 2>&1 | grep 'subject:' | cut -d' ' -f4-)

## prepare subject line for inclusion in command line tool
subj=""
for c in $subj_master; do
   testc=$(echo $c | egrep -o '([A-Z]{1,2})=')
   if [[ $testc ]]; then
       ## new subj section
       subj=$(echo -ne "$subj/$c ")
   else
       ## continue adding to current
       subj=$(echo -ne "$subj$c ")
   fi
done 

subj=${subj//; \//\/} ## ; / to /
subj=${subj//\"/\\\"} ## escape "
subj=${subj//\$\(/\\\$\\\(} ## escape $(
subj=${subj//\`/\\\`} ## escape `

## generate the self signed cert to disk
openssl req -new -x509 -sha256 -key $key_path/master.key -out $key_path/$1.crt -days 365 -subj "$subj"
