# OLSR daemon

# How to Install

## Installing from source

Get your code from the OLSR GitHub:
(see https://github.com/OLSR/olsrd)

 * ``git clone https://github.com/OLSR/olsrd.git``

### Pre-requisites

Download and install the neccessary build requirements

For Debian you will mostly need the following ones:
  * build-essentials: ``sudo apt-get install build-essential dpkg-dev``

## Compiling
  * ``cd olsrd``
  * ``make``
  * (plugins) ``cd lib; for i in $(ls); do cd "$i"; make; cd ..; done``

## Configuring OLSRd

## Starting OLSRd

Assuming your interfaces you want olsrd to listen on are ``eth0, wlan0 and lo`` you could start it like this:

  * ``sudo ./olsrd_static -i eth0 wlan0 lo -d 0 -f olsrd.conf``

You won't see much output though. You can enable more output with with:

  * ``sudo ./olsrd_static -i eth0 -d 1 -f olsrd.conf``

## How to proceed from here

If you managed to start olsrd and see some output, you made it!
Now is the time to review the detailed configuration in file files/olsrd.conf.default.txt
