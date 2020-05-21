IMAGE=bird-fi-test
CONTAINER=bird-fi-test

set -e
docker run --detach --name ${CONTAINER} ${IMAGE}
docker exec ${CONTAINER} bash -c 'echo $PATH'
docker exec ${CONTAINER} bash -c "/usr/local/sbin/bird -c /usr/local/etc/bird.conf"
docker exec ${CONTAINER} bash -c "/usr/local/sbin/birdc show proto"
BGP_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${CONTAINER})
docker exec ${CONTAINER} bash -c "env BGP_IP=$BGP_IP echo \"fi tests here and bgp on ${BGP_IP}\""
