# Splunk Search Scripts.
These scripts were originally written for network admins and/or security engineers/analysts to be able to quickly
track down splunk logs for potential IOCs, or simply troubleshoot devices. 
These scripts are intended to be run from the `bin`. They don't need to be, but that's what I preferred. 
These scripts were written with Windows and PaloAlto logs in splunk specifically. If you use something different,
you'll have to update the scripts accordingly. I hope this is helpful.

## RHEL Python3 Install:
```
dzdo su
yum update
subscription-manager repos --enable rhel-7-server-optional-rpms --enable rhel-server-rhscl-7-rpms
yum -y install @development
yum -y install rh-python36
yum -y install rh-python36-numpy rh-python36-scipy rh-python36-python-tools rh-python36-python-six
scl enable rh-python36 bash
nano /etc/profile.d/python36.sh
```
```
#!/bin/bash
source /opt/rh/rh-python36/enable
export X_SCLS="scl enable rh-python36 'echo $X_SCLS'"
#ctrl+x to exit. Save file.
```
```
#If using a venv# Also, you should be using a venv. Don't be a barbarian.
python3.6 -m venv venv
source venv/bin/activate
python3.6 -m pip install -r requirements.txt
#If using system-wide tools#
umask 022
python3.6 -m pip install --upgrade -r requirements.txt
```


## searchdhcp.py

```
usage: searchdhcp [-h] [-s SEARCH] [-l LINES] [-d [DEDUPE]]

Splunk DHCP search tool.

optional arguments:
  -h, --help            show this help message and exit
  -s SEARCH, --search SEARCH
                        String to search?
  -l LINES, --lines LINES
                        How many lines of output should we print?
  -d [DEDUPE], --dedupe [DEDUPE]
                        Pass this arg to dedupe results by MAC.
```

Args:

`-s` - What are you searching for? Partial hostnames, IPs, and/or MACs accepted.
`-l` - If you want to optionally limit how many lines of output you receive. 
`-d` - Dedupes the results by MAC address. Useful if you don't care about every single DHCP renew event or DNS update. 

Example: `searchdhcp -s 10.0.0.1 -d`
## ---------------------------------------------------------------------------------

## checkfw.py
```
usage: checkfw [-h] [-a [ACTION]] [-d [DEST]] [-o [OUTPUT]] [-s [SOURCE]] [-t TIME] [-u [USER]]

Splunk firewall log search tool. Be smart with your args, or face a mile of output. Script will *attempt* to dedupe output. Use the "-o" flag to print the output you should include in a netadmin ticket.

optional arguments:
  -h, --help            show this help message and exit
  -a [ACTION], --action [ACTION]
                        OPTIONAL: 'allowed' is the only acceptable arg. Scripts default to anything but allowed.
  -d [DEST], --dest [DEST]
                        OPTIONAL: Destination IP for the query?
  -o [OUTPUT], --output [OUTPUT]
                        OPTIONAL: Pass this arg to view the full output for a NADM ticket.
  -s [SOURCE], --source [SOURCE]
                        OPTIONAL: Source IP for the query?
  -t TIME, --time TIME  OPTIONAL: How far back should we look? Default is '30m'. Max is '24h'. Options are: ['15m',
                        '30m', '1h', '4h', '8h', '12h', '16h', '24h']
  -u [USER], --user [USER]
                        OPTIONAL: Scope results to a user?
```

Example: `checkfw -d 8.8.8.8 -s 10.0.0.1 -o -t 15m -u myusername`
## ---------------------------------------------------------------------------------

## u2m.py
```
usage: u2m.py [-h] [-s SEARCH]

This script searches your splunk windows logs for EventCode 4624 to attempt to map usernames to a computer name.

optional arguments:
  -h, --help            show this help message and exit
  -s SEARCH, --search SEARCH
                        Username to search?
```

Example: `u2m -s myusername`
## ---------------------------------------------------------------------------------

