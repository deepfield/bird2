sudo bird -s /var/run/bird -c conf/bird.conf &
echo "bird is running under $(jobs -p) - control socket is /var/run/bird"
