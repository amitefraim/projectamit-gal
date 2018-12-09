SDN FIREWALL BASED ON MININET

Prerequisites:
UBUNTU 16.04, latest MININET, openVSwitch, Python3

Usage:
First we need to correct paths inside files,
change the path "/home/mininet/projectamit-gal" to your local SDN firewall folder
in the following files:
virusNotifier.py
ctrl.py


--
Start gui by running terminal:
cd <project folder>
sudo python3 gui.py
---
For initializing POX, open another terminal and do:
cd <project folder>
sudo python3 pox/pox.py forwarding.l2_learning samples.pretty_log log.level --DEBUG
---
Select size of topology, and press Launch.
MININET will initialize and user will be able to run MININET commands.

i denotes the service number (i runs from 1 to number of services).
j denotes the server number
h0_<i> hosts run virus notifier
h<j>_<i> runs a server.
s<i> is the switch per service.

You may run an attacker from h1 host by calling "h1 python3 attacker.py <ip addr> <attack timeout in  seconds>
