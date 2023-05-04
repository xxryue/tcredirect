/**********************************************************
    > File Name: tc_ingress.bpf.c
    > Author:Edward
    > Mail:xxr_2011@outlook.com
    > Created Time: Thu 04 May 2023 08:45:22 PM CST
 **********************************************************/

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tc_ingress")
int test_tc_ingress(struct __sk_buff *skb){
    return TC_ACT_OK;
}