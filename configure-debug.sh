[[ ! -f ./configure ]] && autoconf
./configure --enable-client --enable-debug --enable-memcheck     "--with-protocols=bfd babel bgp mrt ospf perf pipe radv rip static"     --with-iproutedir=/etc/iproute2

