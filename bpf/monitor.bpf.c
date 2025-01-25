#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// 保持原有的常量定义
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// 保持原有的结构体定义
#pragma pack(push, 1)
struct host_key {
    unsigned char local_mac[ETH_ALEN];
    union {
        __u32 local_ip4;
        __u8  local_ip6[16];
    };
    union {
        __u32 remote_ip4;
        __u8  remote_ip6[16];
    };
    __u16 local_port;
    __u16 remote_port;
    __u8  proto;
    __u8  ip_ver;
};

struct host_stats {
    __u64 rx_bytes;
    __u64 tx_bytes;
};
#pragma pack(pop)

// 保持原有的 map 定义
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct host_key);
    __type(value, struct host_stats);
} host_stats SEC(".maps");

// 保持原有的辅助函数
static __always_inline int is_broadcast_mac(unsigned char *mac) {
    return (mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xff;
}

static __always_inline int is_multicast_mac(unsigned char *mac) {
    return mac[0] & 1;
}

static __always_inline int is_broadcast_ipv4(__u32 addr) {
    return addr == 0xffffffff || addr == 0;
}

static __always_inline int is_multicast_ipv4(__u32 addr) {
    return (addr & 0xf0000000) == 0xe0000000;
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

// 新增: 统一的数据包处理函数
static __always_inline void process_packet(void *data, void *data_end, __u64 pkt_len, int is_ingress) {
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return;

    // 过滤广播和组播
    if (is_broadcast_mac(eth->h_source) || is_multicast_mac(eth->h_source) ||
        is_broadcast_mac(eth->h_dest) || is_multicast_mac(eth->h_dest))
        return;

    struct host_key key = {};
    // 根据方向选择源或目标 MAC
    __builtin_memcpy(key.local_mac, is_ingress ? eth->h_dest : eth->h_source, ETH_ALEN);
    
    void *trans_data;
    __u16 src_port = 0, dst_port = 0;

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = (void*)(eth + 1);
        if ((void*)(iph + 1) > data_end)
            return;

        if (is_broadcast_ipv4(iph->saddr) || is_broadcast_ipv4(iph->daddr) ||
            is_multicast_ipv4(iph->saddr) || is_multicast_ipv4(iph->daddr))
            return;

        key.ip_ver = 4;
        if (is_ingress) {
            key.local_ip4 = iph->daddr;
            key.remote_ip4 = iph->saddr;
        } else {
            key.local_ip4 = iph->saddr;
            key.remote_ip4 = iph->daddr;
        }
        key.proto = iph->protocol;
        
        trans_data = (void*)(iph + 1);
        if (!parse_transport_ports(trans_data, data_end, iph->protocol, &src_port, &dst_port))
            return;

    } else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = (void*)(eth + 1);
        if ((void*)(ip6h + 1) > data_end)
            return;

        if (is_multicast_ipv6(ip6h->saddr.s6_addr) || 
            is_multicast_ipv6(ip6h->daddr.s6_addr))
            return;

        key.ip_ver = 6;
        if (is_ingress) {
            __builtin_memcpy(&key.local_ip6, &ip6h->daddr, sizeof(ip6h->daddr));
            __builtin_memcpy(&key.remote_ip6, &ip6h->saddr, sizeof(ip6h->saddr));
        } else {
            __builtin_memcpy(&key.local_ip6, &ip6h->saddr, sizeof(ip6h->saddr));
            __builtin_memcpy(&key.remote_ip6, &ip6h->daddr, sizeof(ip6h->daddr));
        }
        key.proto = ip6h->nexthdr;
        
        trans_data = (void*)(ip6h + 1);
        if (!parse_transport_ports(trans_data, data_end, ip6h->nexthdr, &src_port, &dst_port))
            return;

    } else {
        return;
    }

    key.local_port = is_ingress ? dst_port : src_port;
    key.remote_port = is_ingress ? src_port : dst_port;

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
            stats->rx_bytes += pkt_len;
        } else {
            stats->tx_bytes += pkt_len;
        }
    }
}

// XDP 程序入口
SEC("xdp")
int xdp_monitor(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // XDP 处理出向流量 (is_ingress = 0)
    process_packet(data, data_end, data_end - data, 0);
    
    return XDP_PASS;
}

// TC 程序入口
SEC("tc")
int tc_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // TC 处理入向流量 (is_ingress = 1)
    process_packet(data, data_end, skb->len, 1);
    
    return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";