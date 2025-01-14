#!/bin/bash



# Generated by: tyk-ci/wf-gen
# Generated on: Tuesday 08 February 2022 12:00:28 PM UTC

# Generation commands:
# ./pr.zsh -repos tyk -base master -branch tt-4363-el7 -title Sync from templates- el7 changes -p
# m4 -E -DxREPO=tyk


echo "Creating user and group..."
GROUPNAME="tyk"
USERNAME="tyk"

getent group "$GROUPNAME" >/dev/null || groupadd -r "$GROUPNAME"
getent passwd "$USERNAME" >/dev/null || useradd -r -g "$GROUPNAME" -M -s /sbin/nologin -c "Tyk service user" "$USERNAME"


# This stopped being a symlink in PR #3569
if [ -L /opt/tyk-gateway/coprocess/python/proto ]; then
    echo "Removing legacy python protobuf symlink"
    rm /opt/tyk-gateway/coprocess/python/proto
fi
