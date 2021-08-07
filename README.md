# UPnProxyPot
An SSDP & UPNP honeypot implementation aimed at intercepting/tracking UPnProxy campaigns.  Presented at Defcon 29, you can watch that presentation here:
https://www.youtube.com/watch?v=mHCGNUsrTf0

------------

### Dependencies
*(list is based on what I used in development and deployment... ymmv)*
- bash
- iptables
- screen
- openssl
- golang ~1.16
- gcc ~11.1.0
- gopacket ~v1.1.19 (go will autofetch @ build time)
- ansible (optional, but highly recommended)

## Some quick notes
### bad ansible is better than no ansible
In the `ansible` directory are some ad hoc scripts that make cluster management easier, you're not required to use these, but they'll save you a lot of typing.  I am going to assume you're going to use them, and if you're not, I suggest you look at what they're doing so you can manually replicate the steps.  Additionally, using `./get_generic.sh "<your cmd here>"` was used quite often to do basic maintenance, log dumping, cleaning, etc.  e.g. `./get_generic.sh "pacman -Syyu --noconfirm"`.

### upnproxy.go vs upnproxy.og.go
`upnproxy.go` is the latest and greatest iteration of the code, including TLS improvements.  These improvements were deployed around the same time that TLS stopped working.  I've included the OG version (`upnproxy.og.go`) that ran for over a year successfully scraping TLS so you can use either.  It's worth noting that I also deployed this older version again after my patches, assuming I had broken the system... and it still didn't work... but for the sake of tinkering and testing, you can see or run either or both.

## Deploying a node
We're assuming you've gotten all of your dependencies setup...
e.g. `./get_generic.sh "pacman --noconfirm -S base-devel iptables go openssl screen"`

### Gen your master key (optional)
Go into the `/scripts/` directory, run `./gen_key.sh` to create a new `/keys/master.key` file, this is the master key that will be used for generating your cloned certs on the fly later.  You don't HAVE to do this, but some diversity in your key here may prevent fingerprinting later.  Additionally you can run this at anytime on the nodes as well, if you'd like key diversity across your cluster.

### Package up your work
Running `./package.sh` will create a `upnproxy.tar.gz` in the `UPnProxyPot` working directory.

### Ansible inventory updated with your nodes
I've included a small script that makes getting your `known_hosts` fingerprints updated, after your nodes are ready and running, run `./add_ssh_fingerprints.sh` so your ad hoc commands will actually work as expected.

### with Ansible ad hoc
Lastly you'll run `./deploy.sh`, which will ask for the SSH password a few times as it works through the process of killing off any nodes that may be actively running, uploading the freshly packaged `upnproxy.tar.gz` file we just generated via `package.sh`, extracting it to disk, building the Go binary, and finally launching a `screen` session and executing `./run.sh` to get the newly uploaded and compiled version up and running.

## Logs, Certs, and PCAPs
### Logging
The `./run.sh` script writes out via `stdout` using `bash` redirection into the file `./upnproxy.log`, this flat file will contain ALL interactions the pot observes, SSDP, injections, and proxy observations.  In the `ansible` directory there are a couple scripts (`get_https_req.sh` & `get_https_req_full.sh`) that will quickly carve out just HTTPS proxy request logs.

If you'd like to pull full logs, the lazy way I did it was via `get_generic.sh` and just dumped the logs across the ansible connection. e.g. `./get_generic.sh "cat upnproxy.log" > upnproxy.logs`

### PCAPs
PCAPs will be automatically captured on proxy sessions, this will give network level visibility that standard logging can't provide, it was initially built into the system for debugging and was just left in place for future debugging and visibility purposes.  These files add up fast in my experiences, you'll probably want to clean these out from time to time if disk space starts to become a problem. e.g. `./get_generic.sh "rm pcaps/*"`

### Certs
Certs are created on the fly, but we never clean them out in any automated fashion, while the files are small, they'll also persist... which isn't a huge problem, but could be an issue if the content of the remote certificate changes.  Deleting `.crt` files from the `keys` directory from time to time isn't a terrible idea imho. e.g. `./get_generic.sh "rm keys/*.crt"`

## Some additional quick notes...
### It runs on Linux...
You can try running this on other OS's, but I never did... it requires iptables, bash, & openssl... so good luck with that. That said, I also only ran it on a bare bones bleeding edge Arch deployments... so, if you're having problems getting it running in other distros, with older versions, etc... well, good luck with that!

![](https://i.imgflip.com/5ityi8.jpg)

### Things that could be better
- logging
	- format
	- location
	- quality
- proper daemonization
- more devices
	- more and randomized SSDP banners
	- more payloads pretending to be more devices
- support content configurable content injection
- better error handling
- better cert cloning/caching (caching linked to Domain...)
- get TLS working again... 
	- CA on the fly that mirrors remote cert 
	- other methods for faking the fingerprint?...

### Old TLS scraping campaign logs
TLS scraping *used* to work... it stopped working, and I believe it has more to do with changes in abuser fingerprinting techniques more than code changes.  I've provided about 50MB of old TLS log entries to show some of the traffic captured while it was functional. I stored them in a separate repo to save everyone bandwidth if they only care about the code and not so much about the previous research.  
##### You can find those logs here: https://github.com/chadillac/UPnProxyPot_logs


