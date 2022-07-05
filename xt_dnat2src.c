#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>

struct ipt_dnat2srcinfo
{
	__be16 port;
};

static int xt_dnat2src_checkentry(const struct xt_tgchk_param *par)
{
	return nf_ct_netns_get(par->net, par->family);
}

static void xt_dnat2src_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_netns_put(par->net, par->family);
}

static unsigned int
xt_dnat2src_target_v0(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct ipt_dnat2srcinfo *info = par->targinfo;
	struct nf_nat_range2 range;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *hdr = ip_hdr(skb);

	ct = nf_ct_get(skb, &ctinfo);
	WARN_ON(!(ct != NULL &&
		 (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED)));

	memset(&range, 0, sizeof(range));
	range.flags = NF_NAT_RANGE_MAP_IPS;
	range.min_addr.ip = hdr->saddr;
	range.max_addr.ip = hdr->saddr;
	if (info->port) {
		range.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
		range.min_proto.all = info->port;
		range.max_proto.all = info->port;
	}

	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
}

static struct xt_target xt_dnat2src_target_reg[] __read_mostly = {
	{
		.name		= "DNAT2SRC",
		.revision	= 0,
		.checkentry	= xt_dnat2src_checkentry,
		.destroy	= xt_dnat2src_destroy,
		.target		= xt_dnat2src_target_v0,
		.targetsize	= sizeof(struct ipt_dnat2srcinfo),
		.family		= NFPROTO_IPV4,
		.table		= "nat",
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_OUT),
		.me		= THIS_MODULE,
	},
};

static int __init xt_dnat2src_init(void)
{
	return xt_register_targets(xt_dnat2src_target_reg, ARRAY_SIZE(xt_dnat2src_target_reg));
}

static void __exit xt_dnat2src_exit(void)
{
	xt_unregister_targets(xt_dnat2src_target_reg, ARRAY_SIZE(xt_dnat2src_target_reg));
}

module_init(xt_dnat2src_init);
module_exit(xt_dnat2src_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ye Donggang dg_ye@163.com");
MODULE_ALIAS("ipt_DNAT2SRC");
MODULE_DESCRIPTION("DNAT to skb ip src targets support");

