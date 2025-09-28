#!/bin/bash
set -e

# Function to setup host user mapping
setup_host_user() {
    HOST_USER_ID=${HOST_USER_ID:-$(stat -c %u /data/ErroneousZoneGeneration 2>/dev/null || echo 1000)}
    HOST_GROUP_ID=${HOST_GROUP_ID:-$(stat -c %g /data/ErroneousZoneGeneration 2>/dev/null || echo 1000)}

    echo "Setting up for host user ${HOST_USER_ID}:${HOST_GROUP_ID}"

    # Create group if it does not exist
    if ! getent group $HOST_GROUP_ID >/dev/null 2>&1; then
        groupadd -g $HOST_GROUP_ID research
    fi

    # Create user if it does not exist
    if ! getent passwd $HOST_USER_ID >/dev/null 2>&1; then
        useradd -u $HOST_USER_ID -g $HOST_GROUP_ID -m -s /bin/bash research
    fi

    # Create research output directories with correct ownership
    mkdir -p /data/ErroneousZoneGeneration/tmp/{test-results,temp,logs}
    chown -R $HOST_USER_ID:$HOST_GROUP_ID /data/ErroneousZoneGeneration/tmp/test-results
    chown -R $HOST_USER_ID:$HOST_GROUP_ID /data/ErroneousZoneGeneration/tmp/temp
    chown -R $HOST_USER_ID:$HOST_GROUP_ID /data/ErroneousZoneGeneration/tmp/logs

    # Set permissions to be group-writable
    chmod -R 775 /data/ErroneousZoneGeneration/tmp/test-results
    chmod -R 775 /data/ErroneousZoneGeneration/tmp/temp
    chmod -R 775 /data/ErroneousZoneGeneration/tmp/logs

    export RESEARCH_USER_ID=$HOST_USER_ID
    export RESEARCH_GROUP_ID=$HOST_GROUP_ID
}

# Main setup
echo "=== Docker Container Starting ==="

# Only do user setup if we have the research volume mounted
if [ -d "/data/ErroneousZoneGeneration" ]; then
    setup_host_user
fi

# Always setup BIND permissions
chown -R bind:bind /data/bind1 /data/bind2

echo "=== Starting Services ==="

# Execute the original command
exec "$@"

EXPOSE 2222