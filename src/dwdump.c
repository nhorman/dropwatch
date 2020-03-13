/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <errno.h>
#include <inttypes.h>
#include <getopt.h>
#include <pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/socket.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/socket.h>
#include <sys/time.h>

#include "net_dropmon.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static struct nla_policy net_dm_policy[NET_DM_ATTR_MAX + 1] = {
	[NET_DM_ATTR_ALERT_MODE]		= { .type = NLA_U8 },
	[NET_DM_ATTR_TRUNC_LEN]			= { .type = NLA_U32 },
	[NET_DM_ATTR_QUEUE_LEN]			= { .type = NLA_U32 },
	[NET_DM_ATTR_STATS]			= { .type = NLA_NESTED },
	[NET_DM_ATTR_HW_STATS]			= { .type = NLA_NESTED },
};

static struct nla_policy
net_dm_stats_policy[NET_DM_ATTR_STATS_MAX + 1] = {
	[NET_DM_ATTR_STATS_DROPPED]		= { .type = NLA_U64 },
};

static bool stop;

enum dwdump_pkt_origin {
	DWDUMP_PKT_ORIGIN_ALL,
	DWDUMP_PKT_ORIGIN_SW,
	DWDUMP_PKT_ORIGIN_HW,
};

struct dwdump_options {
	const char *dumpfile;
	__u32 trunc_len;
	bool query;
	__u32 queue_len;
	bool passive;
	bool stats;
	int rxbuf;
	bool exit;
	enum dwdump_pkt_origin origin;
	bool need_pcap;
	bool need_mon;
};

struct dwdump {
	struct nl_sock *csk, *dsk;
	pcap_t *pcap_handle;
	pcap_dumper_t *pcap_dumper;
	struct dwdump_options options;
	int family;
	long snaplen;
	char *pcap_buf, *pkt;
};

/* Based on https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html */
struct linux_sll {
	__be16 pkttype;
	__be16 hatype;
	__be16 halen;
	unsigned char addr[8];
	__be16 family;
};

static int dwdump_data_init(struct dwdump *dwdump)
{
	struct nl_sock *sk;
	int family, err;

	sk = nl_socket_alloc();
	if (!sk) {
		fprintf(stderr, "Failed to allocate data socket\n");
		return -1;
	}

	/* Add wiggle room for other netlink attributes in addition to the
	 * payload.
	 */
	dwdump->snaplen = dwdump->options.trunc_len + 2048;
	dwdump->pkt = calloc(1, dwdump->snaplen);
	if (!dwdump->pkt) {
		perror("calloc");
		goto err_pkt_alloc;
	}

	err = genl_connect(sk);
	if (err) {
		fprintf(stderr, "Failed to connect data socket\n");
		goto err_genl_connect;
	}

	family = genl_ctrl_resolve(sk, "NET_DM");
	if (family < 0) {
		fprintf(stderr, "Failed to resolve ID of \"NET_DM\" family\n");
		goto err_genl_ctrl_resolve;
	}

	err = nl_socket_set_buffer_size(sk, dwdump->options.rxbuf, 0);
	if (err < 0) {
		fprintf(stderr, "Failed to set receive buffer size of data socket\n");
		goto err_set_buffer_size;
	}

	err = nl_socket_add_memberships(sk, NET_DM_GRP_ALERT, NFNLGRP_NONE);
	if (err) {
		fprintf(stderr, "Failed to join multicast group\n");
		goto err_add_memberships;
	}

	dwdump->dsk = sk;
	dwdump->family = family;

	return 0;

err_add_memberships:
err_set_buffer_size:
err_genl_ctrl_resolve:
err_genl_connect:
	free(dwdump->pkt);
err_pkt_alloc:
	nl_socket_free(sk);
	return -1;
}

static void dwdump_data_fini(struct dwdump *dwdump)
{
	nl_socket_drop_memberships(dwdump->dsk, NET_DM_GRP_ALERT, NFNLGRP_NONE);
	free(dwdump->pkt);
	nl_socket_free(dwdump->dsk);
}

static const char *dwdump_alert_mode(uint8_t alert_mode)
{
	switch (alert_mode) {
	case NET_DM_ALERT_MODE_SUMMARY:
		return "summary";
	case NET_DM_ALERT_MODE_PACKET:
		return "packet";
	}

	return "invalid alert mode";
}

static int dwdump_config_set(struct dwdump *dwdump)
{
	struct nl_sock *sk = dwdump->csk;
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message\n");
		return -1;
	}

	if (!genlmsg_put(msg, 0, NL_AUTO_SEQ, dwdump->family, 0,
			 NLM_F_REQUEST|NLM_F_ACK, NET_DM_CMD_CONFIG, 0))
		goto genlmsg_put_failure;

	if (nla_put_u8(msg, NET_DM_ATTR_ALERT_MODE, NET_DM_ALERT_MODE_PACKET))
		goto nla_put_failure;

	if (nla_put_u32(msg, NET_DM_ATTR_TRUNC_LEN, dwdump->options.trunc_len))
		goto nla_put_failure;

	if (nla_put_u32(msg, NET_DM_ATTR_QUEUE_LEN, dwdump->options.queue_len))
		goto nla_put_failure;

	err = nl_send_sync(sk, msg);
	if (err < 0) {
		fprintf(stderr, "Failed to configure drop monitor kernel module\n");
		return err;
	}

	return 0;

nla_put_failure:
genlmsg_put_failure:
	nlmsg_free(msg);
	return -EMSGSIZE;
}

static int dwdump_config_get(struct dwdump *dwdump)
{
	struct nlattr *attrs[NET_DM_ATTR_MAX + 1];
	struct sockaddr_nl nla;
	unsigned char *buf;
	uint8_t alert_mode;
	int len, err;

	err = genl_send_simple(dwdump->csk, dwdump->family,
			       NET_DM_CMD_CONFIG_GET, 0, NLM_F_REQUEST);
	if (err < 0) {
		fprintf(stderr, "Failed to query configuration\n");
		return -1;
	}

	len = nl_recv(dwdump->csk, &nla, &buf, NULL);
	if (len < 0)
		return -1;

	err = genlmsg_parse((void *) buf, 0, attrs, NET_DM_ATTR_MAX,
			    net_dm_policy);
	if (err < 0)
		return -1;

	if (!attrs[NET_DM_ATTR_ALERT_MODE] || !attrs[NET_DM_ATTR_TRUNC_LEN] ||
	    !attrs[NET_DM_ATTR_QUEUE_LEN])
		return -1;

	alert_mode = nla_get_u8(attrs[NET_DM_ATTR_ALERT_MODE]);
	printf("Alert mode: %s\n", dwdump_alert_mode(alert_mode));

	printf("Truncation length: %u\n",
	       nla_get_u32(attrs[NET_DM_ATTR_TRUNC_LEN]));

	printf("Queue length: %u\n", nla_get_u32(attrs[NET_DM_ATTR_QUEUE_LEN]));

	return 0;
}

static void dwdump_nested_stats_print(struct nlattr *attr)
{
	struct nlattr *attrs[NET_DM_ATTR_STATS_MAX + 1];
	int err;

	err = nla_parse_nested(attrs, NET_DM_ATTR_STATS_MAX, attr,
			       net_dm_stats_policy);
	if (err)
		return;

	if (attrs[NET_DM_ATTR_STATS_DROPPED])
		printf("Tail dropped: %" PRIu64 "\n",
		       nla_get_u64(attrs[NET_DM_ATTR_STATS_DROPPED]));
}

static int dwdump_stats_get(struct dwdump *dwdump)
{
	struct nlattr *attrs[NET_DM_ATTR_MAX + 1];
	struct sockaddr_nl nla;
	unsigned char *buf;
	int len, err;

	err = genl_send_simple(dwdump->csk, dwdump->family,
			       NET_DM_CMD_STATS_GET, 0, NLM_F_REQUEST);
	if (err < 0) {
		fprintf(stderr, "Failed to query statistics\n");
		return -1;
	}

	len = nl_recv(dwdump->csk, &nla, &buf, NULL);
	if (len < 0)
		return -1;

	err = genlmsg_parse((void *) buf, 0, attrs, NET_DM_ATTR_MAX,
			    net_dm_policy);
	if (err < 0)
		return -1;

	if (attrs[NET_DM_ATTR_STATS]) {
		printf("Software statistics:\n");
		dwdump_nested_stats_print(attrs[NET_DM_ATTR_STATS]);
	}

	if (attrs[NET_DM_ATTR_HW_STATS]) {
		printf("Hardware statistics:\n");
		dwdump_nested_stats_print(attrs[NET_DM_ATTR_HW_STATS]);
	}

	return 0;
}

static int dwdump_monitor_origin_put(const struct dwdump *dwdump,
				     struct nl_msg *msg)
{
	switch (dwdump->options.origin) {
	case DWDUMP_PKT_ORIGIN_ALL:
		if (nla_put_flag(msg, NET_DM_ATTR_SW_DROPS) ||
		    nla_put_flag(msg, NET_DM_ATTR_HW_DROPS))
			return -EMSGSIZE;
		break;
	case DWDUMP_PKT_ORIGIN_SW:
		if (nla_put_flag(msg, NET_DM_ATTR_SW_DROPS))
			return -EMSGSIZE;
		break;
	case DWDUMP_PKT_ORIGIN_HW:
		if (nla_put_flag(msg, NET_DM_ATTR_HW_DROPS))
			return -EMSGSIZE;
		break;
	}

	return 0;
}

static int dwdump_monitor(struct dwdump *dwdump, bool start)
{
	uint8_t cmd = start ? NET_DM_CMD_START : NET_DM_CMD_STOP;
	struct nl_sock *sk = dwdump->csk;
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message\n");
		return -1;
	}

	if (!genlmsg_put(msg, 0, NL_AUTO_SEQ, dwdump->family, 0,
			 NLM_F_REQUEST|NLM_F_ACK, cmd, 0))
		goto genlmsg_put_failure;

	err = dwdump_monitor_origin_put(dwdump, msg);
	if (err < 0)
		goto genlmsg_put_failure;

	err = nl_send_sync(sk, msg);
	if (err < 0) {
		fprintf(stderr, "Failed to %s monitoring\n",
			start ? "start" : "stop");
		return err;
	}

	return 0;

genlmsg_put_failure:
	nlmsg_free(msg);
	return -EMSGSIZE;
}

static void dwdump_handler(int sig)
{
	stop = true;
}

static int dwdump_sighandler_install(void)
{
	static const int signals_catch[] = {
		SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGHUP,
	};
	struct sigaction saction;
	int i, err;

	memset(&saction, 0, sizeof(saction));
	saction.sa_handler = dwdump_handler;

        for (i = 0; i < ARRAY_SIZE(signals_catch); i++) {
                err = sigaction(signals_catch[i], &saction, NULL);
		if (err) {
			perror("sigaction");
			return err;
		}
	}

	return 0;
}

static int dwdump_ctrl_init(struct dwdump *dwdump)
{
	struct nl_sock *sk;
	int err;

	sk = nl_socket_alloc();
	if (!sk) {
		fprintf(stderr, "Failed to allocate control socket\n");
		return -1;
	}

	err = genl_connect(sk);
	if (err) {
		fprintf(stderr, "Failed to connect control socket");
		goto err_genl_connect;
	}

	dwdump->csk = sk;

	if (!dwdump->options.need_mon)
		return 0;

	err = dwdump_config_set(dwdump);
	if (err)
		goto err_config_set;

	err = dwdump_monitor(dwdump, true);
	if (err)
		goto err_monitor;

	return 0;

err_monitor:
err_config_set:
err_genl_connect:
	nl_socket_free(sk);
	return err;
}

static void dwdump_ctrl_fini(struct dwdump *dwdump)
{
	if (!dwdump->options.need_mon)
		goto out;

	dwdump_monitor(dwdump, false);
out:
	nl_socket_free(dwdump->csk);
}

static void dwdump_pcap_write(struct dwdump *dwdump, unsigned char *buf,
			      int len)
{
	struct pcap_pkthdr hdr;
	int pkt_len;

	if (len + sizeof(struct linux_sll) < dwdump->snaplen)
		pkt_len = len + sizeof(struct linux_sll);
	else
		pkt_len = dwdump->snaplen - sizeof(struct linux_sll);

	memcpy(dwdump->pcap_buf + sizeof(struct linux_sll), buf, pkt_len);

	hdr.caplen = pkt_len;
	hdr.len = pkt_len;
	gettimeofday(&hdr.ts, NULL);

	pcap_dump((unsigned char *) dwdump->pcap_dumper, &hdr,
		  (const unsigned char *) dwdump->pcap_buf);
	/* In case packets are written to stdout, make sure each packet is
	 * immediately written and not buffered.
	 */
	fflush(NULL);
}

static int dwdump_pcap_buf_init(struct dwdump *dwdump)
{
	struct linux_sll sll;

	/* The wireshark netlink dissector expects netlink messages to start
	 * with a Linux cooked header (SLL), so include it before each packet.
	 */
	memset(&sll, 0, sizeof(sll));
	sll.pkttype = htons(PACKET_OUTGOING);
	sll.hatype = htons(ARPHRD_NETLINK);
	sll.family = htons(AF_NETLINK);

	dwdump->pcap_buf = calloc(1, dwdump->snaplen);
	if (!dwdump->pcap_buf) {
		perror("calloc");
		return -1;
	}

	memcpy(dwdump->pcap_buf, &sll, sizeof(sll));

	return 0;
}

static void dwdump_pcap_buf_fini(struct dwdump *dwdump)
{
	free(dwdump->pcap_buf);
}

static int dwdump_pcap_genl_init(struct dwdump *dwdump)
{
	struct sockaddr_nl nla;
	unsigned char *buf;
	int len, err;

	/* In order for wireshark to be able to invoke the net_dm dissector,
	 * it must learn about the mapping between the generic netlink
	 * family ID and its name from this dump.
	 *
	 * Reference:
	 * https://www.wireshark.org/lists/wireshark-users/201907/msg00027.html
	 */
	err = genl_send_simple(dwdump->csk, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
			       1, NLM_F_DUMP);
	if (err < 0) {
		fprintf(stderr, "Failed to dump generic netlink families\n");
		return -1;
	}

	len = nl_recv(dwdump->csk, &nla, &buf, NULL);
	if (len < 0)
		return -1;

	dwdump_pcap_write(dwdump, buf, len);

	return 0;
}

static int dwdump_pcap_init(struct dwdump *dwdump)
{
	int err;

	if (!dwdump->options.need_pcap)
		return 0;

	dwdump->pcap_handle = pcap_open_dead(DLT_NETLINK, dwdump->snaplen);
	if (!dwdump->pcap_handle) {
		perror("pcap_open_dead");
		return -1;
	}

	dwdump->pcap_dumper = pcap_dump_open(dwdump->pcap_handle,
					     dwdump->options.dumpfile);
	if (!dwdump->pcap_dumper) {
		pcap_perror(dwdump->pcap_handle, "pcap_dump_open");
		goto err_dump_open;
	}

	err = dwdump_pcap_buf_init(dwdump);
	if (err)
		goto err_buf_init;

	err = dwdump_pcap_genl_init(dwdump);
	if (err)
		goto err_genl_init;

	return 0;

err_genl_init:
	dwdump_pcap_buf_fini(dwdump);
err_buf_init:
	pcap_dump_close(dwdump->pcap_dumper);
err_dump_open:
	pcap_close(dwdump->pcap_handle);
	return -1;
}

static void dwdump_pcap_fini(struct dwdump *dwdump)
{
	if (!dwdump->options.need_pcap)
		return;

	dwdump_pcap_buf_fini(dwdump);
	pcap_dump_close(dwdump->pcap_dumper);
	pcap_close(dwdump->pcap_handle);
}

static int dwdump_init(struct dwdump *dwdump)
{
	int err;

	err = dwdump_data_init(dwdump);
	if (err)
		return err;

	err = dwdump_ctrl_init(dwdump);
	if (err)
		goto err_ctrl_init;

	err = dwdump_pcap_init(dwdump);
	if (err)
		goto err_pcap_init;

	err = dwdump_sighandler_install();
	if (err)
		goto err_sighandler_install;

	return 0;

err_sighandler_install:
	dwdump_pcap_fini(dwdump);
err_pcap_init:
	dwdump_ctrl_fini(dwdump);
err_ctrl_init:
	dwdump_data_fini(dwdump);
	return err;
}

static void dwdump_fini(struct dwdump *dwdump)
{
	dwdump_pcap_fini(dwdump);
	dwdump_ctrl_fini(dwdump);
	dwdump_data_fini(dwdump);
}

static int dwdump_main(struct dwdump *dwdump)
{
	int fd = nl_socket_get_fd(dwdump->dsk);

	if (dwdump->options.query)
		return dwdump_config_get(dwdump);

	if (dwdump->options.stats)
		return dwdump_stats_get(dwdump);

	if (dwdump->options.exit)
		return dwdump_monitor(dwdump, false);

	while (!stop) {
		int len;

		/* Use recv() instead of nl_recv() since interruption of
		 * nl_recv() causes the operation to be retried.
		 */
		len = recv(fd, dwdump->pkt, dwdump->snaplen, 0);
		if (len < 0) {
			switch (errno) {
			case EINTR: /* fall-through */
			case ENOBUFS:
				continue;
			default:
				perror("recv");
				return -1;
			}
		}

		dwdump_pcap_write(dwdump, (unsigned char *) dwdump->pkt, len);
	}

	return 0;
}

static int dwdump_origin_parse(struct dwdump *dwdump, const char *origin)
{
	if (strcmp(origin, "sw") == 0) {
		dwdump->options.origin = DWDUMP_PKT_ORIGIN_SW;
		return 0;
	} else if (strcmp(origin, "hw") == 0) {
		dwdump->options.origin = DWDUMP_PKT_ORIGIN_HW;
		return 0;
	} else {
		fprintf(stderr, "Invalid origin: \'%s\'\n", origin);
		return -EINVAL;
	}
}

static void dwdump_usage(FILE *fp)
{
	fprintf(fp, "Usage:\n");
	fprintf(fp, "dwdump [ -w <file> -t <length> -q -l <limit> -p -s -b <size> -e -o <sw|hw> ]\n");
	fprintf(fp, " -w <file> dump packets to provided file. defaults to standard output\n");
	fprintf(fp, " -t <length> truncate packets to provided length. defaults to no truncation\n");
	fprintf(fp, " -q query the kernel for current configuration and exit\n");
	fprintf(fp, " -l <limit> set packet queue limit to provided limit\n");
	fprintf(fp, " -p only listen on notified packets with no configuration\n");
	fprintf(fp, " -s query kernel for statistics and exit\n");
	fprintf(fp, " -b <size> set the socket's receive buffer to provided size\n");
	fprintf(fp, " -o monitor only <sw|hw> originated drops. defaults to all\n");
	fprintf(fp, " -e ask kernel to stop monitoring and exit\n");
}

static int dwdump_opts_parse(struct dwdump *dwdump, int argc, char **argv)
{
	static const struct option long_options[] = {
		{ "write",		required_argument,	NULL, 'w' },
		{ "trunc",		required_argument,	NULL, 't' },
		{ "query",		no_argument,		NULL, 'q' },
		{ "limit",		required_argument,	NULL, 'l' },
		{ "passive",		no_argument,		NULL, 'p' },
		{ "stats",		no_argument,		NULL, 's' },
		{ "bufsize",		required_argument,	NULL, 'b' },
		{ "origin",		required_argument,	NULL, 'o' },
		{ "exit",		no_argument,		NULL, 'e' },
		{ "help",		no_argument,		NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	static const char optstring[] = "w:t:ql:psb:o:eh";
	int opt, err;

	/* Default values */
	dwdump->options.dumpfile = "/dev/stdout";
	dwdump->options.trunc_len = 0xffff;
	dwdump->options.queue_len = 1000;
	dwdump->options.rxbuf = 1024 * 1024;
	dwdump->options.origin = DWDUMP_PKT_ORIGIN_ALL;
	dwdump->options.need_pcap = true;
	dwdump->options.need_mon = true;

	while ((opt = getopt_long(argc, argv, optstring,
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'w':
			dwdump->options.dumpfile = optarg;
			break;
		case 't':
			dwdump->options.trunc_len = atol(optarg);
			if (dwdump->options.trunc_len == 0 ||
			    dwdump->options.trunc_len > 0xffff)
				dwdump->options.trunc_len = 0xffff;
			break;
		case 'q':
			dwdump->options.query = true;
			dwdump->options.need_pcap = false;
			dwdump->options.need_mon = false;
			break;
		case 'l':
			dwdump->options.queue_len = atol(optarg);
			break;
		case 'p':
			dwdump->options.passive = true;
			dwdump->options.need_mon = false;
			break;
		case 's':
			dwdump->options.stats = true;
			dwdump->options.need_pcap = false;
			dwdump->options.need_mon = false;
			break;
		case 'b':
			dwdump->options.rxbuf = atol(optarg);
			break;
		case 'o':
			err = dwdump_origin_parse(dwdump, optarg);
			if (err)
				return err;
			break;
		case 'e':
			dwdump->options.exit = true;
			dwdump->options.need_pcap = false;
			dwdump->options.need_mon = false;
			break;
		case 'h':
			dwdump_usage(stdout);
			return -1;
		case '?':
			dwdump_usage(stderr);
			return -1;
		default:
			fprintf(stderr, "Unknown option: \'%c\'\n", opt);
			dwdump_usage(stderr);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct dwdump *dwdump;
	int err;

	dwdump = calloc(1, sizeof(*dwdump));
	if (!dwdump) {
		perror("calloc");
		goto err_dwdump_alloc;
	}

	err = dwdump_opts_parse(dwdump, argc, argv);
	if (err)
		goto err_opts_parse;

	err = dwdump_init(dwdump);
	if (err)
		goto err_dwdump_init;

	err = dwdump_main(dwdump);

	dwdump_fini(dwdump);
	free(dwdump);

	return err;

err_dwdump_init:
err_opts_parse:
	free(dwdump);
err_dwdump_alloc:
	exit(EXIT_FAILURE);
}
