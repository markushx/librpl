# A RPL implementation for Linux derived from the Contiki RPL implementation.

This library is unlike the Contiki RPL implementation supposed to run
on the host computer; not on the microcontroller. It is supposed to
work with the 6LoWPAN Linux kernel implementation.

## Compile instructions:

make
sudo LD_LIBRARY_PATH=. ./examples/rpl-root-node -i lowpan0 -s ::1

## Status:
* Compiles.
* Sends DIOs on the specified interface.

## TODOs:
* Accept and interprete DAOs.
* Set routes using netlink, libnl or 'ip route'.
