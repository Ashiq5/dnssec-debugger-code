#!/bin/bash
# Enhanced start.sh with better permission handling

echo "=== Enhanced DNSSEC Container Start ==="

# Get user info for later use
RESEARCH_USER_ID=${RESEARCH_USER_ID:-$(stat -c %u /data/ErroneousZoneGeneration 2>/dev/null || echo 1000)}
RESEARCH_GROUP_ID=${RESEARCH_GROUP_ID:-$(stat -c %g /data/ErroneousZoneGeneration 2>/dev/null || echo 1000)}

echo "Research user: ${RESEARCH_USER_ID}:${RESEARCH_GROUP_ID}"

# ROOT OPERATIONS (must stay as root)
echo "Setting up network interfaces..."
ip addr add 129.88.71.95/24 dev lo
ip addr add 129.88.71.96/24 dev lo

echo "Verifying BIND permissions..."
chown -R bind:bind /data/bind1 /data/bind2

echo "Starting BIND instance 1 on 129.88.71.95..."
/usr/sbin/named -c /data/bind1/named.conf -u bind -n 1 -4 -g > /var/log/named1.log 2>&1 &
BIND1_PID=$!

echo "Starting BIND instance 2 on 129.88.71.96..."
/usr/sbin/named -c /data/bind2/named.conf -u bind -n 1 -4 -g > /var/log/named2.log 2>&1 &
BIND2_PID=$!

echo "Starting SSH daemon..."
/usr/sbin/sshd -D &
SSH_PID=$!

# Wait a moment for services to start
sleep 3

# Check if services started successfully
if ! kill -0 $BIND1_PID 2>/dev/null; then
    echo "ERROR: BIND instance 1 failed to start"
    cat /var/log/named1.log
    exit 1
fi

if ! kill -0 $BIND2_PID 2>/dev/null; then
    echo "ERROR: BIND instance 2 failed to start"
    cat /var/log/named2.log
    exit 1
fi

echo "=== All Services Started Successfully ==="
echo "BIND1 PID: $BIND1_PID"
echo "BIND2 PID: $BIND2_PID"
echo "SSH PID: $SSH_PID"

# Function to cleanup on exit
cleanup() {
    echo "Shutting down services..."
    kill $BIND1_PID $BIND2_PID $SSH_PID 2>/dev/null || true
    wait
}

trap cleanup SIGTERM SIGINT

# Keep container alive and show logs
tail -f /var/log/named1.log /var/log/named2.log &
TAIL_PID=$!

# Wait for services
wait $BIND1_PID $BIND2_PID $SSH_PID $TAIL_PID