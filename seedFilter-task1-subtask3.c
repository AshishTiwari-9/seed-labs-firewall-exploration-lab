#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static struct nf_hook_ops hook1, hook2;
unsigned int preventPing(void *priv, struct sk_buff *skb,
                         const struct nf_hook_state *state) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  struct icmphdr *icmph;
  iph = ip_hdr(skb);
  tcph = tcp_hdr(skb);
  icmph = icmp_hdr(skb);
  if (iph->protocol == IPPROTO_ICMP && icmph->type == ICMP_ECHO) {
    printk(KERN_INFO "Ping attempted.\n");
    return NF_DROP;
  }
  return NF_ACCEPT;
}
unsigned int preventTelnet(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  iph = ip_hdr(skb);
  tcph = tcp_hdr(skb);
  if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23)) {
    printk(KERN_INFO "Telnet attempted\n");
    return NF_DROP;
  }
  return NF_ACCEPT;
}
int registerFilter(void) {
printk(KERN_INFO "Registering all filters from seedFilter...
\n");
hook1.hook = preventPing;
hook1.hooknum = NF_INET_PRE_ROUTING;
hook1.pf = PF_INET;
hook1.priority = NF_IP_PRI_FIRST;
nf_register_net_hook(&init_net, &hook1);
hook2.hook = preventTelnet;
hook2.hooknum = NF_INET_PRE_ROUTING;
hook2.pf = PF_INET;
hook2.priority = NF_IP_PRI_FIRST;
nf_register_net_hook(&init_net, &hook2);
printk(KERN_INFO "Registered all filters from seedFilter.
\n");
return 0;
}
void removeFilter(void) {
  printk(KERN_INFO "Removing filters...\n");
  nf_unregister_net_hook(&init_net, &hook1);
  nf_unregister_net_hook(&init_net, &hook2);
  printk(KERN_INFO "Removed all filters from seedFilter\n");
}

module_init(registerFilter);
module_exit(removeFilter);
MODULE_LICENSE(“GPL");