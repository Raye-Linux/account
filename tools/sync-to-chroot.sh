#!/bin/sh
# Copies the working tree into the agents' build chroot (build output stays there).
set -e
dst=/var/tmp/raye/agents/build/account/src
mkdir -p "$dst"
tar -C /srv/raye/account -cf - --exclude=.git --exclude=target . | tar -C "$dst" -xf -
