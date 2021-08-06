#!/usr/bin/env bash

echo "killing procs..."
ansible -i inventory.yaml all -k -m shell -a "killall screen"

echo "uploading new package..."
ansible -i inventory.yaml all -k -m copy -a "src=../upnproxy.tar.gz dest=~"

## NOTE: we rebuild the binary on the machine to ensure architecture compatability
##       because depending on your dev/package machine and your deployment endpoint
##       architecture... you could be pushing incompatible software to your nodes
##
##       e.g. running ./package.sh on a Mac will result in upnproxy bin being MachO... not ELF...
##            and I'm willing to bet your intended endpoint node will be a Linux box...
echo "extracting files and building binary..."
ansible -i inventory.yaml all -k -m shell -a 'tar xvzf upnproxy.tar.gz; go build upnproxy.go'

echo "starting sensor screen sessions..."
ansible -i inventory.yaml all -k -m shell -a 'screen -dmS run -t run; screen -S run -p 0 -X stuff "./run.sh"'
