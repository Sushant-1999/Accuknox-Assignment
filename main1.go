package main

import (
	"fmt"
	"log"
	"os"

	"github.com/iovisor/gobpf/bcc"
)

const source = `
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sched.h>

#define DEFAULT_ALLOW_PORT 4040
#define TASK_COMM_LEN 16

BPF_HASH(proc_port_map, char[TASK_COMM_LEN], int);

int drop_process_port(struct __sk_buff *skb) {
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

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    int *port = proc_port_map.lookup(&comm);
    if (!port || tcp->dest != __constant_htons(*port))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}
`

func main() {
	module := bcc.NewModule(source, []string{})
	defer module.Close()

	fn, err := module.Load("drop_process_port", bcc.BPFTcClassifier)
	if err != nil {
		log.Fatalf("Failed to load function: %s\n", err)
	}

	err = module.AttachTc("eth0", fn, "ingress")
	if err != nil {
		log.Fatalf("Failed to attach tc: %s\n", err)
	}

	processName := "myprocess"
	port := 4040
	if len(os.Args) > 2 {
		processName = os.Args[1]
		fmt.Sscanf(os.Args[2], "%d", &port)
	}

	table := bcc.NewTable(module.TableId("proc_port_map"), module)
	key := make([]byte, 16)
	copy(key, processName)
	leaf := make([]byte, 4)
	bcc.PutInt(leaf, port)

	table.Set(key, leaf)

	fmt.Printf("Allowing traffic only on port %d for process %s\n", port, processName)

	select {} // Keep the program running
}
