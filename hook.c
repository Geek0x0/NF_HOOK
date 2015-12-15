#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("caydyn <caydyn@icloud.com>");
MODULE_DESCRIPTION("netfilter hook");

enum { 
    NF_IP_PRE_ROUTING,
	NF_IP_LOCAL_IN,
	NF_IP_FORWARD,
	NF_IP_LOCAL_OUT,
	NF_IP_POST_ROUTING,
	NF_IP_NUMHOOKS
};

static struct nf_hook_ops nfho;
struct sk_buff *sock_buff;

unsigned int
hookfn(const struct nf_hook_ops *ops, struct sk_buff *skb,
       const struct net_device *in, const struct net_device *out,
       int (*okfn) (struct sk_buff *))
{
    uint8_t proto;
    struct ethhdr *eth;
	struct iphdr *ipv4h;
    struct ipv6hdr *ipv6h;

    char message[128] = { 0 };

	if (!skb)
		return NF_ACCEPT;

    memset(message, 0, 128);

    eth = (struct ethhdr *)skb_mac_header(skb);
    switch(ntohs(eth->h_proto))
    {
        case ETH_P_IP:
            {
                strcpy(message, "got ipv4 ");
	            ipv4h = (struct iphdr *) skb_network_header(skb);
                proto = ipv4h->protocol;
            }
            break;
        case ETH_P_IPV6:
            {
                strcpy(message, "got ipv6 ");
	            ipv6h = (struct ipv6hdr *) skb_network_header(skb);
                proto = ipv6h->nexthdr;
            }
            break;
        default:
            printk(KERN_INFO "l3 protocol: %X\n", eth->h_proto);
    }

    switch(proto)
    {
        case IPPROTO_TCP:
            strcat(message, "tcp packet");
            break;
        case IPPROTO_UDP:
            strcat(message, "udp packet");
            break;
        case IPPROTO_ICMP:
            strcat(message, "icmp packet");
            break;
    }

    printk(KERN_INFO "%s\n", message);

	return NF_ACCEPT;
}


static int __init hook_init(void)
{
	nfho.hook = hookfn;
	nfho.hooknum = NF_IP_LOCAL_IN;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfho);

	return 0;
}

static void __exit hook_exit(void)
{
	nf_unregister_hook(&nfho);
}

module_init(hook_init);
module_exit(hook_exit);
