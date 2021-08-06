#!/usr/bin/env bash
cnt=""
if [[ "$1" != "" ]]; then
    cnt="| tail -n $1 "
fi
ansible -i inventory.yaml all -k -m shell -a "grep 'Method' upnproxy.log --binary-files=text | egrep -o 'URL:(.+) ' $cnt | cut -d' ' -f1"
