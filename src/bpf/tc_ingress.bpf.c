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

#define TARGET_PORT     8080


#define L4_UDP_CSUM_OFFSET (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define L4_UDP_DEST_OFFSET (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define L4_UDP_SOURCE_OFFSET (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define L4_TCP_CUSM_OFFSET  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define L4_TCP_DEST_OFFSET  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define L4_TCP_SOURCE_OFFSET  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define L3_TOT_LEN_OFFSET   (ETH_HLEN + offsetof(struct iphdr, tot_len))
#define L3_CSUM_OFFSET   (ETH_HLEN + offsetof(struct iphdr, check))
static void ingress_redirect(struct __sk_buff *skb){
    struct iphdr ip;
    struct udphdr udp;
    struct tcphdr tcp;
    int ip_offset, l4_offset;
    __be16 old_dest;
    int i = 0;
    __u8 *data = (__u8*)(__u64)skb->data;
    __be16 new_dest = __bpf_constant_htons(TARGET_PORT);
    ip_offset = ETH_HLEN;
    if(bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(struct iphdr)) < 0){
        return;
    }
    l4_offset = ip_offset + (ip.ihl << 2);
    if(ip.protocol == IPPROTO_UDP){
        if(bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(struct udphdr)) < 0){
            return;
        }

        bpf_printk("ingress[%02X,%02X]", ip.saddr,
                   ip.daddr);
        if(udp.dest != __bpf_constant_htons(80)){
            return;
        }
        old_dest = udp.dest;
        bpf_l4_csum_replace(skb, L4_UDP_CSUM_OFFSET, old_dest, new_dest, sizeof(__be16));
        bpf_skb_store_bytes(skb, L4_UDP_DEST_OFFSET, &new_dest, sizeof(__be16), 0);
        bpf_printk("[UDP] change to %d",TARGET_PORT);
    }
    if(ip.protocol == IPPROTO_TCP){
        if(bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(struct tcphdr)) < 0){
            return;
        }
        if(tcp.dest != __bpf_constant_htons(80)){
            return;
        }
        old_dest = tcp.dest;
        bpf_l4_csum_replace(skb, L4_TCP_CUSM_OFFSET, old_dest, new_dest, sizeof(__be16));
        bpf_skb_store_bytes(skb, L4_TCP_DEST_OFFSET, &new_dest, sizeof(__be16), 0);
        bpf_printk("[TCP ingress] change to %d",TARGET_PORT);
    }
}

SEC("tc_ingress")
int test_tc_ingress(struct __sk_buff *skb){
    if(skb->protocol != __bpf_constant_htons(ETH_P_IP)){
        return TC_ACT_OK;
    }
    ingress_redirect(skb);
    return TC_ACT_OK;
}

static void egress_redirect(struct __sk_buff *skb){
    struct iphdr ip;
    struct udphdr udp;
    struct tcphdr tcp;
    int ip_offset, l4_offset;
    __be16 old_source;
    __be16 new_source = __bpf_constant_htons(80);
    ip_offset = ETH_HLEN;
    if(bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(struct iphdr)) < 0){
        return;
    }
    l4_offset = ip_offset + (ip.ihl << 2);

    if(ip.protocol == IPPROTO_UDP){
        if(bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(struct udphdr)) < 0){
            return;
        }

        if(udp.source != __bpf_constant_htons(TARGET_PORT)){
            return;
        }
        old_source = udp.source;
        bpf_l4_csum_replace(skb, L4_UDP_CSUM_OFFSET, old_source, new_source, sizeof(__be16));
        bpf_skb_store_bytes(skb, L4_UDP_SOURCE_OFFSET, &new_source, sizeof(__be16), 0);
        bpf_printk("[UDP] change to %d",TARGET_PORT);
    }
    if(ip.protocol == IPPROTO_TCP){
        if(bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(struct tcphdr)) < 0){
            return;
        }
        if(tcp.source != __bpf_constant_htons(TARGET_PORT)){
            return;
        }
        old_source = tcp.source;
        bpf_l4_csum_replace(skb, L4_TCP_CUSM_OFFSET, old_source, new_source, sizeof(__be16));
        bpf_skb_store_bytes(skb, L4_TCP_SOURCE_OFFSET, &new_source, sizeof(__be16), 0);
        bpf_printk("[TCP egress] change to %d",TARGET_PORT);
    }
}

SEC("tc_egress")
int test_tc_egress(struct __sk_buff *skb){
    if(skb->protocol != __bpf_constant_htons(ETH_P_IP)){
        return TC_ACT_OK;
    }
    egress_redirect(skb);
    return TC_ACT_OK;
}
static __u32 value = 0x12340488;
//static __u32 value = 0;
static void _add_tag(struct __sk_buff *skb){
    struct iphdr ip;
    int ip_offset = ETH_HLEN;
    struct tcphdr tcp;
    int l4_offset;
    int options_offset = 0;
    __u16 old_tot_len, new_tot_len;
    __u8 header_len;
    __u8 temp;
    __u16 old_header2 = 0, new_header2 = 0;
    if(bpf_skb_load_bytes(skb, ip_offset, &temp, sizeof(__u8)) < 0){
        return;
    }
    if(bpf_skb_load_bytes(skb, ip_offset, &old_header2, sizeof(__u16)) < 0){
        return;
    }
    if(bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(struct iphdr)) < 0){
        return;
    }

    if(ip.protocol == IPPROTO_UDP){
        return;
    }
    l4_offset = ip_offset + (ip.ihl << 2);
    if(ip.protocol == IPPROTO_TCP){
        if(bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(struct tcphdr)) < 0){
            return;
        }
        if(tcp.dest != __bpf_constant_htons(80)){
            return;
        }
    }
    bpf_printk("1 ihl[%d], tot_len[%d]", ip.ihl, bpf_ntohs(ip.tot_len));
    header_len = ip.ihl;

    options_offset = ip_offset + (header_len << 2);
    old_tot_len = __bpf_ntohs(ip.tot_len);
    if(bpf_skb_adjust_room(skb, 4, BPF_ADJ_ROOM_NET, 0) < 0){
        bpf_printk("adjust room failed\n");
        return;
    }
    if(bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(struct iphdr)) < 0){
        return;
    }
    bpf_printk("2 ihl[%d], tot_len[%d]", ip.ihl, bpf_ntohs(ip.tot_len));

    new_tot_len = old_tot_len + 4;
    new_tot_len = bpf_htons(new_tot_len);
    bpf_l3_csum_replace(skb, L3_CSUM_OFFSET, ip.tot_len, new_tot_len, sizeof(__u16));
    old_header2 = bpf_ntohs(old_header2);
    new_header2 = old_header2 & 0xF0FF;
    bpf_printk("new_header[%d], old_header[%d]\n", bpf_ntohs(new_header2), bpf_ntohs(old_header2));
    header_len += 1;
    temp = temp & 0xF0;
    temp += header_len;
    new_header2 = (temp<<8) | new_header2;
    new_header2 = bpf_htons(new_header2);
    old_header2 = bpf_htons(old_header2);
    bpf_printk("new_header[%d], old_header[%d]\n", bpf_ntohs(new_header2), bpf_ntohs(old_header2));
    bpf_l3_csum_replace(skb, L3_CSUM_OFFSET, old_header2, new_header2, sizeof(__u16));
    bpf_l3_csum_replace(skb, L3_CSUM_OFFSET, 0, value, 0);
    bpf_skb_store_bytes(skb, options_offset, &value, sizeof(__u32), 0);
    bpf_skb_store_bytes(skb, L3_TOT_LEN_OFFSET, &new_tot_len, sizeof(__u16), 0);
    bpf_skb_store_bytes(skb, ip_offset, &new_header2, sizeof(__u16), 0);
    if(bpf_skb_load_bytes(skb, ip_offset, &ip, sizeof(struct iphdr)) < 0){
        return;
    }
    bpf_printk("3 ihl[%d], tot_len[%d]\n", ip.ihl, bpf_ntohs(ip.tot_len));
}
SEC("tc_add_tag")
int add_tag(struct __sk_buff *skb){
    if(skb->protocol != __bpf_constant_htons(ETH_P_IP)){
        return TC_ACT_OK;
    }
    _add_tag(skb);
    return TC_ACT_OK;
}