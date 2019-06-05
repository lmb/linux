#!/bin/bash -e
# SPDX-License-Identifier: GPL-2.0

if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        echo "FAIL"
        exit 1
fi

# Run the script in a dedicated network namespace.
if [[ -z $(ip netns identify $$) ]]; then
        exec ../net/in_netns.sh "$0" "$@"
fi

tc qdisc add dev lo clsact
tc filter add dev lo ingress bpf direct-action object-file ./test_sk_assign.o \
	section "sk_assign_test"

exec ./test_sk_assign
