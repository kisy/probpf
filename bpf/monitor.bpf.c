// vmlinux.h 包含所有内核类型定义 (通过 BTF 生成)
// 注意：vmlinux.h 必须在其他头文件之前包含
#include "vmlinux.h"

// BPF 辅助函数和宏
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// 协议常量定义（vmlinux.h 不包含这些）
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

// 保持原有的常量定义
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// 保持原有的结构体定义
struct host_key {
    unsigned char client_mac[ETH_ALEN];
    union {
        __u32 client_ip4; // Union 1: Client IP
        __u8  client_ip6[16];
    };
    union {
        __u32 remote_ip4; // Union 2: Remote IP
        __u8  remote_ip6[16];
    };
    __u16 remote_port;
    __u16 src_port;
    __u8  proto;
    __u8  ip_ver;
};

// ... (Stats struct and map def tailored to match) ...
struct host_stats {
    __u64 rx_bytes;
    __u64 tx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct host_key);
    __type(value, struct host_stats);
} host_stats SEC(".maps");

// Per-CPU 缓冲区用于 fentry 程序暂存数据包内容
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8[512]);  // 512 字节缓冲区
} packet_buffer SEC(".maps");

// 辅助函数
static __always_inline int is_broadcast_mac(unsigned char *mac) {
    return (mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xff;
}

static __always_inline int is_multicast_mac(unsigned char *mac) {
    return (mac[0] & 0x01) == 0x01;
}

static __always_inline int is_zero_mac(unsigned char *mac) {
    return (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0;
}

static __always_inline int is_broadcast_ipv4(__u32 addr) {
    return addr == 0xffffffff || addr == 0;
}

static __always_inline int is_multicast_ipv4(__u32 addr) {
    return (bpf_ntohl(addr) & 0xf0000000) == 0xe0000000;
}

static __always_inline int is_multicast_ipv6(__u8 *addr) {
    return addr[0] == 0xff;
}

static __always_inline int parse_transport_ports(void *trans_data, void *data_end,
                                               __u8 proto,
                                               __u16 *src_port, __u16 *dst_port) {
    struct tcphdr *tcp;
    struct udphdr *udp;
    
    switch (proto) {
    case IPPROTO_TCP:
        tcp = trans_data;
        if ((void*)(tcp + 1) > data_end)
            return 0;
        *src_port = bpf_ntohs(tcp->source);
        *dst_port = bpf_ntohs(tcp->dest);
        break;
    case IPPROTO_UDP:
        udp = trans_data;
        if ((void*)(udp + 1) > data_end)
            return 0;
        *src_port = bpf_ntohs(udp->source);
        *dst_port = bpf_ntohs(udp->dest);
        break;
    default:
        return 0;
    }
    return 1;
}

// ...

static __always_inline void process_packet(void *data, void *data_end, __u64 pkt_len, int is_ingress) {
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return;

    if (is_broadcast_mac(eth->h_source) || is_multicast_mac(eth->h_source) || is_zero_mac(eth->h_source) ||
        is_broadcast_mac(eth->h_dest) || is_multicast_mac(eth->h_dest) || is_zero_mac(eth->h_dest))
        return;

    struct host_key key = {};
    // Client MAC is always the one on our LAN
    // Ingress: Source is Client
    // Egress: Dest is Client
    __builtin_memcpy(key.client_mac, is_ingress ? eth->h_source : eth->h_dest, ETH_ALEN);
    
    void *trans_data;
    __u16 src_port = 0, dst_port = 0;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    void *cursor = (void*)(eth + 1);

    // 1. Check for single VLAN
    if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
        struct vlan_hdr *vlan = cursor;
        if ((void*)(vlan + 1) > data_end)
            return;
        
        h_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        cursor += sizeof(struct vlan_hdr);

        // 2. Check for double VLAN (QinQ)
        if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
            vlan = cursor;
            if ((void*)(vlan + 1) > data_end)
                return;
            
            h_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
            cursor += sizeof(struct vlan_hdr);
        }
    }

    if (h_proto == ETH_P_IP) {
        struct iphdr *iph = cursor;
        if ((void*)(iph + 1) > data_end)
            return;

        if (is_broadcast_ipv4(iph->saddr) || is_broadcast_ipv4(iph->daddr) ||
            is_multicast_ipv4(iph->saddr) || is_multicast_ipv4(iph->daddr))
            return;

        __u32 ip_hlen = iph->ihl * 4;
        if (ip_hlen < sizeof(struct iphdr))
            return;

        key.ip_ver = 4;
        // Client IP Assignment
        if (is_ingress) {
            // Client -> Internet
            key.client_ip4 = iph->saddr; // Source is Client
            key.remote_ip4 = iph->daddr; // Dest is Remote
        } else {
            // Internet -> Client
            key.client_ip4 = iph->daddr; // Dest is Client
            key.remote_ip4 = iph->saddr; // Source is Remote
        }
        key.proto = iph->protocol;
        
        trans_data = (void*)iph + ip_hlen;
        parse_transport_ports(trans_data, data_end, iph->protocol, &src_port, &dst_port);

            
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = cursor;
        if ((void*)(ip6h + 1) > data_end)
            return;

        if (is_multicast_ipv6((__u8 *)&ip6h->saddr) ||
            is_multicast_ipv6((__u8 *)&ip6h->daddr))
            return;

        key.ip_ver = 6;
        if (is_ingress) {
            __builtin_memcpy(&key.client_ip6, &ip6h->saddr, sizeof(ip6h->saddr));
            __builtin_memcpy(&key.remote_ip6, &ip6h->daddr, sizeof(ip6h->daddr));
        } else {
            __builtin_memcpy(&key.client_ip6, &ip6h->daddr, sizeof(ip6h->daddr));
            __builtin_memcpy(&key.remote_ip6, &ip6h->saddr, sizeof(ip6h->saddr));
        }
        key.proto = ip6h->nexthdr;
        
        trans_data = (void*)(ip6h + 1);
        parse_transport_ports(trans_data, data_end, ip6h->nexthdr, &src_port, &dst_port);

    } else {
        return;
    }

    // Ports
    // Ingress (Client->Remote): src=Client, dst=Remote
    // Egress (Remote->Client): src=Remote, dst=Client
    // Ports
    if (is_ingress) {
        key.remote_port = dst_port;
        key.src_port = src_port;
    } else {
        key.remote_port = src_port;
        key.src_port = dst_port;
    }
    
    struct host_stats *stats, newstats = {};
    stats = bpf_map_lookup_elem(&host_stats, &key);
    if (!stats) {
        if (is_ingress) {
            newstats.rx_bytes = pkt_len;
        } else {
            newstats.tx_bytes = pkt_len;
        }
        bpf_map_update_elem(&host_stats, &key, &newstats, BPF_ANY);
    } else {
        if (is_ingress) {
            __sync_fetch_and_add(&stats->rx_bytes, pkt_len);
        } else {
            __sync_fetch_and_add(&stats->tx_bytes, pkt_len);
        }
    }
}

// XDP 程序入口
SEC("xdp")
int xdp_monitor(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // XDP 处理入向流量 (is_ingress = 1)
    process_packet(data, data_end, data_end - data, 1);
    
    return XDP_PASS;
}

// fentry 程序入口 - 用于出向流量统计
SEC("fentry/dev_hard_start_xmit")
int BPF_PROG(fentry_egress_monitor, struct sk_buff *skb, struct net_device *dev)
{
    if (!skb)
        return 0;
    
    unsigned int len = skb->len;
    
    // 限制最大读取长度
    if (len > 1514)
        len = 1514;
    
    // 从 per-cpu map 获取缓冲区（避免栈溢出）
    __u32 key = 0;
    __u8 (*buffer)[512] = bpf_map_lookup_elem(&packet_buffer, &key);
    if (!buffer)
        return 0;
    
    unsigned int read_len = len < sizeof(*buffer) ? len : sizeof(*buffer);
    
    // 使用 bpf_probe_read_kernel 将数据搬运到 map 缓冲区
    // 直接使用 skb->data 作为源地址
    if (bpf_probe_read_kernel(buffer, read_len, skb->data) < 0)
        return 0;
    
    // 传递缓冲区给 process_packet 解析
    void *data_start = (void *)buffer;
    void *data_end = data_start + read_len;
    
    process_packet(data_start, data_end, len, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";