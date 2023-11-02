#
# running a simple sanity test
#
if [[ -e *.mrt ]]
then
	rm *.mrt
fi

if [[ $(gobgp --version) != 'gobgp version 3.20.0' ]]
then
	echo "You are running the wrong version of gobgp ( $(gobgp --version) )"
	exit 1
fi

source run_bird.sh
source run_gobgp.sh

echo "Waiting 5s for things to settle and BGP to do its thing" && sleep 5

source inject_test_routes.sh

echo "Done injecting routes"
echo "Waiting another 10s for the mrts to be written"
sleep 10

# shutdown bird
sudo birdc -s /var/run/bird down
