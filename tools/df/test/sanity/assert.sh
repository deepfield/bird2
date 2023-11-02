# improves readability
fail() {
    echo $1
    exit 1
}

assert() {
    file="$1"
    fieldname="$2"
    fieldnum="$3"
    expected="$4"

    actual=$(cut -f$fieldnum '-d|' $file)

    msg="$file: $fieldname{fn=$fieldnum) was ($actual) not ($expected)"

    # a kludge but right now comparing everything as string is ok
    [ "$actual" != "$expected" ] && fail "$msg"
}

BGPDUMP=/home/support/pipedream/third-party/ripencc-bgpdump/bgpdump

# field definition
FN_AFISAFI=1
FN_TIMESTAMP=2
FN_NEIGHBOR=4
FN_NEIGHBOR_ASN=5
FN_CIDR=6
FN_ASPATH=7
FN_ORIGIN=8
FN_NEXTHOP=9
FN_MED=10
FN_COMMUNITY=12

for x in *.mrt
do
    ${BGPDUMP} -m $x -O ${x/.mrt/.txt} >/dev/null 2>&1
done

#
# some expected values
#
neighbor="172.27.0.6"
neighbor_asn="65002"

# ipv4
file=testv4.txt
[ ! -e $file ] && fail "ipv4 test output does not exist"
assert $file "neighbor" $FN_NEIGHBOR $neighbor
assert $file "neighbor_asn" $FN_NEIGHBOR_ASN $neighbor_asn
assert $file "route cidr" $FN_CIDR "192.168.0.0/24"
assert $file "aspath" $FN_ASPATH "65002"
assert $file "origin" $FN_ORIGIN "INCOMPLETE"
assert $file "nexthop" $FN_NEXTHOP "172.27.0.6"
assert $file "community" $FN_COMMUNITY "no-export no-advertise"

# ipv6
file=testv6.txt
[ ! -e $file ] && fail "ipv6 test output does not exist"
assert $file "neighbor" $FN_NEIGHBOR $neighbor
assert $file "neighbor_asn" $FN_NEIGHBOR_ASN $neighbor_asn
assert $file "route cidr" $FN_CIDR "2001:555:dead:beef::/128"
assert $file "aspath" $FN_ASPATH "65002"
assert $file "origin" $FN_ORIGIN "INCOMPLETE"
assert $file "nexthop" $FN_NEXTHOP "::172.27.0.6"
assert $file "community" $FN_COMMUNITY "no-export no-advertise"

# ipv4 mpls
file=testv4mpls.txt
[ ! -e $file ] && fail "ipv4 mpls test output does not exist"
assert $file "neighbor" $FN_NEIGHBOR $neighbor
assert $file "neighbor_asn" $FN_NEIGHBOR_ASN $neighbor_asn
assert $file "route cidr" $FN_CIDR "192.168.1.0/24" 
assert $file "aspath" $FN_ASPATH "65002"
assert $file "origin" $FN_ORIGIN "INCOMPLETE"
assert $file "nexthop" $FN_NEXTHOP "172.27.0.6"
assert $file "community" $FN_COMMUNITY "65535:65284"

# ivp6 mpls
file=testv6mpls.txt
[ ! -e $file ] && fail "ipv6 mpls test output does not exist"
assert $file "neighbor" $FN_NEIGHBOR $neighbor
assert $file "neighbor_asn" $FN_NEIGHBOR_ASN $neighbor_asn
assert $file "route cidr" $FN_CIDR "2001:db8:beef::/52"
assert $file "aspath" $FN_ASPATH "65002"
assert $file "origin" $FN_ORIGIN "INCOMPLETE"
assert $file "nexthop" $FN_NEXTHOP "::172.27.0.6"
assert $file "community" $FN_COMMUNITY "65535:65284"

# vpn4
file=testvpn4.txt
[ ! -e $file ] && fail "ipv6 mpls test output does not exist"
assert $file "neighbor" $FN_NEIGHBOR $neighbor
assert $file "neighbor_asn" $FN_NEIGHBOR_ASN $neighbor_asn
assert $file "route cidr" $FN_CIDR "8.8.8.0/24"
assert $file "aspath" $FN_ASPATH "65002"
assert $file "origin" $FN_ORIGIN "INCOMPLETE"
assert $file "nexthop" $FN_NEXTHOP "::172.27.0.6"
assert $file "community" $FN_COMMUNITY "65535:65284"

# vpn6
# field indexes are off there is an extra field in here
file=testvpn6.txt
[ ! -e $file ] && fail "ipv6 mpls test output does not exist"
assert $file "neighbor" $FN_NEIGHBOR $neighbor
assert $file "neighbor_asn" $FN_NEIGHBOR_ASN $neighbor_asn
assert $file "route cidr" $FN_CIDR "2001:555:dead:beef::/128"
assert $file "aspath" $FN_ASPATH "65002"
assert $file "origin" $FN_ORIGIN "INCOMPLETE"
assert $file "nexthop" $FN_NEXTHOP "::172.27.0.6"
assert $file "community" $FN_COMMUNITY "65535:65284"

echo "All tests passed"
