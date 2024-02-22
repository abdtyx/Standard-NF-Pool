#!/bin/bash
sudo sh -c "echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
sudo sh -c "echo 2 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages"
sudo sh -c "echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages"
sudo sh -c "echo 2 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages"
sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"
sudo mount -t hugetlbfs -o pagesize=1G none /mnt/huge

