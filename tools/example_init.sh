#!/bin/bash 

#load vfio driver 
modprobe vfio-pci 

#bind PCI devices to vfio-pci driver
dpdk-devbind.py -b vfio-pci 0000:01:00.0
dpdk-devbind.py -b vfio-pci 0000:01:00.1

#reserve 1G hugepage 
./tools/make_hugepagefs.sh 8

echo "Initialization complete."