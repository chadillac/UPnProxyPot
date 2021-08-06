#!/usr/bin/env bash

echo "starting sensor screen sessions..."
ansible -i inventory.yaml all -k -m shell -a 'screen -dmS run -t run; screen -S run -p 0 -X stuff "./run.sh"'
