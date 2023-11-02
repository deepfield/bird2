#
# this file injects the test routes
# feel free to add other options to the individual address families
#
# ivp4
gobgp global rib add -a ipv4 192.168.0.0/24 nexthop $MYIP community no-export,no-advertise
# ipv6
gobgp global rib add -a ipv6 2001:555:dead:beef::/128 nexthop ::$MYIP community no-export,no-advertise origin incomplete
# ipv4 mpls
gobgp global rib add -a ipv4-mpls 192.168.1.0/24 0 nexthop $MYIP community no-peer
# ipv6 mpls
gobgp global rib add -a ipv6-mpls 2001:db8:beef::/52 0 nexthop ::$MYIP community no-peer

# vpn4
gobgp global rib add -a vpnv4 8.8.8.0/24 label 100 rd 100:100 origin incomplete nexthop 172.22.0.0 aspath 6919,16534 community no-export,no-advertise
# vpn6
gobgp global rib add -a vpnv6 2001:555:dead:beef::/128 label 100 rd 65002:100 nexthop ::$MYIP community no-export,no-advertise,no-peer
