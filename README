# Standard NF Pool

## Installation

Install [DPDK](https://core.dpdk.org/) before `make`

## Setup

Run `./setup.sh`

## Utilization

Some dpdk args should be specified before the application args. 

`sudo ./build/[app_name] -c 0x1 --vdev 'net_pcap0,iface=enp3s0,phy_mac=1' -- --arg1 1 --arg2 2`

For example, if we want to run `aes_encrypt`:

```bash
cd examples
make
cd aes_encrypt
sudo ./build/aesencrypt -c 0x1 --vdev 'net_pcap0,iface=enp3s0,phy_mac=1' -- -d DST [-p PRINT_DELAY]
```

Note that `iface` should be set to custom value. In the example, `enp3s0` is used.

Here we provide an example for each NF:

```bash
sudo ./build/aes_encrypt -c 0x1 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -d 2 -p 1
sudo ./build/aes_decrypt -c 0x1 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -d 2 -p 1
sudo ./build/arp_response -c 0x1 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -d 2 -s 192.168.0.123 -p
sudo ./build/basic_monitor -c 0x1 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -p 1
sudo ./build/bridge -c 0x1 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -p 1
sudo ./build/firewall -c 0x1 --vdev 'net_pcap0,iface=enp3s0,phy_mac=1' -- -b -d 2 -f rules.json -p 1
sudo ./build/flow_table -l 0,2,4,6 -n 4 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -d 2 -p 1
sudo ./build/flow_tracker -c 0x1 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -d 2 -p 1
sudo ./build/l2fwd -c 0x1 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -k 0x1 -p 1 -m
sudo ./build/l3fwd -c 0x1 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -k 0x1 -p 1 -e -h 7
sudo ./build/load_generator -c 0x1 --vdev 'net_pcap0,iface=wlo1,phy_mac=1' -- -d 2 -p 1 -t 100 -m ab:cd:ef:12:34:56 -s 100 -o
```

Some NFs support pcap file replay. To enable pcap, set the `ENABLE_PCAP` to 1 in `Makefile`. Then the NF will try to load packets from `sample.pcap`.