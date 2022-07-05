#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <xtables.h>
#include <iptables.h> /* get_kernel_version */
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nf_nat.h>

struct ipt_dnat2srcinfo
{
	__be16 port;
};

static void DNAT2SRC_help(void)
{
	printf(
"DNAT2SRC target options:\n"
"--to-port\n");
}

#define s struct ipt_dnat2srcinfo
static const struct xt_option_entry DNAT2SRC_opts[] = {
	{.name = "to-port", .id = 0, .type = XTTYPE_PORT,
	.flags = XTOPT_NBO | XTOPT_PUT, XTOPT_POINTER(s, port)},
	XTOPT_TABLEEND,
};
#undef s

static void DNAT2SRC_parse(struct xt_option_call *cb)
{
	const struct ipt_entry *entry = cb->xt_entry;

	if (!(entry->ip.proto == IPPROTO_TCP
	    || entry->ip.proto == IPPROTO_UDP
	    || entry->ip.proto == IPPROTO_SCTP
	    || entry->ip.proto == IPPROTO_DCCP
	    || entry->ip.proto == IPPROTO_ICMP)) {
			xtables_error(PARAMETER_PROBLEM, "DNAT2SRC proto must be set");
	}

	xtables_option_parse(cb);
}

static void DNAT2SRC_fcheck(struct xt_fcheck_call *cb)
{
}

static void DNAT2SRC_print(const void *ip, const struct xt_entry_target *target,
                       int numeric)
{
	const struct ipt_dnat2srcinfo *info = (const void *)target->data;
	if (info->port != 0)
		printf(" to-port %u", ntohs(info->port));
}

static void DNAT2SRC_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_dnat2srcinfo *info = (const void *)target->data;
	if (info->port != 0)
		printf(" --to-port %u", ntohs(info->port));
}

static int DNAT2SRC_xlate(struct xt_xlate *xl, const struct xt_xlate_tg_params *params)
{
	return 1;
}

static struct xtables_target dnat2src_tg_reg[] = {
	{
		.name		= "DNAT2SRC",
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_IPV4,
		.revision	= 0,
		.size		= XT_ALIGN(sizeof(struct ipt_dnat2srcinfo)),
		.userspacesize	= XT_ALIGN(sizeof(struct ipt_dnat2srcinfo)),
		.help		= DNAT2SRC_help,
		.print		= DNAT2SRC_print,
		.save		= DNAT2SRC_save,
		.x6_parse	= DNAT2SRC_parse,
		.x6_fcheck	= DNAT2SRC_fcheck,
		.x6_options	= DNAT2SRC_opts,
		.xlate		= DNAT2SRC_xlate,
	},
};

void _init(void)
{
	xtables_register_targets(dnat2src_tg_reg, ARRAY_SIZE(dnat2src_tg_reg));
}


