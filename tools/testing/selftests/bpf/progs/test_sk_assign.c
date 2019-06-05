// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Cloudflare Ltd.

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";

/* Fill 'tuple' with L3 info, and attempt to find L4. On fail, return NULL. */
static struct bpf_sock_tuple *get_tuple(void *data, __u64 nh_off,
					void *data_end, __u16 eth_proto,
					bool *ipv4)
{
	struct bpf_sock_tuple *result;
	__u8 proto = 0;
	__u64 ihl_len;

	if (eth_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)(data + nh_off);

		if (iph + 1 > data_end)
			return NULL;
		if (iph->ihl != 5)
			/* Options are not supported */
			return NULL;
		ihl_len = iph->ihl * 4;
		proto = iph->protocol;
		*ipv4 = true;
		result = (struct bpf_sock_tuple *)&iph->saddr;
	} else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + nh_off);

		if (ip6h + 1 > data_end)
			return NULL;
		ihl_len = sizeof(*ip6h);
		proto = ip6h->nexthdr;
		*ipv4 = false;
		result = (struct bpf_sock_tuple *)&ip6h->saddr;
	} else {
		return NULL;
	}

	if (result + 1 > data_end || proto != IPPROTO_TCP)
		return NULL;

	return result;
}

SEC("sk_assign_test")
int bpf_sk_assign_test(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = (struct ethhdr *)(data);
	struct bpf_sock_tuple *tuple, ln = {0};
	struct bpf_sock *sk;
	int tuple_len;
	bool ipv4;
	int ret;

	if (eth + 1 > data_end)
		return TC_ACT_SHOT;

	tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &ipv4);
	if (!tuple)
		return TC_ACT_SHOT;

	tuple_len = ipv4 ? sizeof(tuple->ipv4) : sizeof(tuple->ipv6);
	sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
	if (sk) {
		if (sk->state != BPF_TCP_LISTEN)
			goto assign;

		bpf_sk_release(sk);
	}

	if (ipv4) {
		if (tuple->ipv4.dport != bpf_htons(4321))
			return TC_ACT_OK;

		ln.ipv4.daddr = bpf_htonl(0x7f000001);
		ln.ipv4.dport = bpf_htons(1234);

		sk = bpf_skc_lookup_tcp(skb, &ln, sizeof(ln.ipv4),
					BPF_F_CURRENT_NETNS, 0);
	} else {
		if (tuple->ipv6.dport != bpf_htons(4321))
			return TC_ACT_OK;

		/* Upper parts of daddr are already zero. */
		ln.ipv6.daddr[3] = bpf_htonl(0x1);
		ln.ipv6.dport = bpf_htons(1234);

		sk = bpf_skc_lookup_tcp(skb, &ln, sizeof(ln.ipv6),
					BPF_F_CURRENT_NETNS, 0);
	}

	/* We can't do a single skc_lookup_tcp here, because then the compiler
	 * will likely spill tuple_len to the stack. This makes it lose all
	 * bounds information in the verifier, which then rejects the call as
	 * unsafe.
	 */
	if (!sk)
		return TC_ACT_SHOT;

	if (sk->state != BPF_TCP_LISTEN) {
		bpf_sk_release(sk);
		return TC_ACT_SHOT;
	}

assign:
	ret = bpf_sk_assign(skb, sk, 0);
	bpf_sk_release(sk);
	return ret == 0 ? TC_ACT_OK : TC_ACT_SHOT;
}
