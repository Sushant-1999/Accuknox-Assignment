#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define DEFAULT_DROP_PORT 4040

BPF_TABLE("array", int, int, drop_port, 1);

int drop_tcp_port(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, 0, sizeof(*eth));
    if (!eth)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = bpf_hdr_pointer(skb, sizeof(*eth), sizeof(*ip));
    if (!ip)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = bpf_hdr_pointer(skb, sizeof(*eth) + sizeof(*ip), sizeof(*tcp));
    if (!tcp)
        return TC_ACT_OK;

    int key = 0;
    int *port = drop_port.lookup(&key);
    if (!port)
        return TC_ACT_OK;

    if (tcp->dest == __constant_htons(*port))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}
