#include <linux/module.h>
#include <linux/netfilter.h>


static unsigned int ipv4_pkt_handler(
	void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	(void)priv;
	(void)skb;
	(void)state;

	printk("%s(), %d\n", __FUNCTION__, __LINE__);

	return NF_QUEUE_NR(0);
}

static struct nf_hook_ops test_hooks[] = {
	{
	    .hook = &ipv4_pkt_handler,
	    .pf = NFPROTO_IPV4,
	    .hooknum = NF_INET_LOCAL_IN,
	    .priority = -3000,
	},
	{
	    .hook = &ipv4_pkt_handler,
	    .pf = NFPROTO_IPV4,
	    .hooknum = NF_INET_POST_ROUTING,
	    .priority = -3000,
	}
};


static int __init nf_test_init(void)
{
	printk("%s(), %d\n", __FUNCTION__, __LINE__);

	if (nf_register_net_hooks(&init_net, test_hooks, ARRAY_SIZE(test_hooks)) < 0) {
		pr_crit("nf_register_net_hooks failed\n");
		return -1;
	}

	return 0;
}

static void __exit nf_test_exit(void)
{
	printk("%s(), %d\n", __FUNCTION__, __LINE__);
	nf_unregister_net_hooks(&init_net, test_hooks, ARRAY_SIZE(test_hooks));
}


module_init(nf_test_init);
module_exit(nf_test_exit);
 
MODULE_LICENSE("GPL");


