# run the daemon in the background
if [[ ${MYIP} == '' ]]
then
	echo "You must set the environmental variable MYIP to the ip address to be used for testing"
	exit 1
fi
gobgpd --disable-stdlog &
echo "Waiting for gobgd for 3s" && sleep 3
echo "gobgpd is running with pid $(jobs -p)"
# configure the bgp server instance
gobgp global as 65002 router-id 10.0.0.2 listen-port 17000 listen-addresses $MYIP
# add bird neighbor
gobgp nei add $MYIP as 65000 family ipv4-unicast,ipv6-unicast,l3vpn-ipv4-unicast,l3vpn-ipv6-unicast,ipv4-labelled-unicast,ipv6-labelled-unicast
# configure vrf for vpn
gobgp vrf add globalvrf rd 2:2 rt both 2:2

