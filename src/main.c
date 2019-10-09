/*
 * Copyright (C) 2009, Neil Horman <nhorman@redhat.com>
 *
 * This program file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program in a file named COPYING; if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA
 */

/*
 * Opens our netlink socket.  Returns the socket descriptor or < 0 on error
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <asm/types.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "net_dropmon.h"
#include "lookup.h"

/*
 * This is just in place until the kernel changes get comitted
 */
#ifndef NETLINK_DRPMON
#define NETLINK_DRPMON 20
#endif

struct netlink_message {
	void *msg;
	struct nl_msg *nlbuf;
	int refcnt;
	LIST_ENTRY(netlink_message) ack_list_element;
	int seq;
	void (*ack_cb)(struct netlink_message *amsg, struct netlink_message *msg, int err);
};

LIST_HEAD(ack_list, netlink_message);

struct ack_list ack_list_head = {NULL};

unsigned long alimit = 0;
unsigned long acount = 0;
unsigned long trunc_len = 0;
unsigned long queue_len = 0;
bool monitor_sw = false;
bool monitor_hw = false;

void handle_dm_alert_msg(struct netlink_message *msg, int err);
void handle_dm_packet_alert_msg(struct netlink_message *msg, int err);
void handle_dm_config_new_msg(struct netlink_message *msg, int err);
void handle_dm_stats_new_msg(struct netlink_message *msg, int err);
void handle_dm_config_msg(struct netlink_message *amsg, struct netlink_message *msg, int err);
void handle_dm_start_msg(struct netlink_message *amsg, struct netlink_message *msg, int err);
void handle_dm_stop_msg(struct netlink_message *amsg, struct netlink_message *msg, int err);
int disable_drop_monitor();

static void(*type_cb[_NET_DM_CMD_MAX])(struct netlink_message *, int err) = {
	NULL,
	handle_dm_alert_msg,
	NULL,
	NULL,
	NULL,
	handle_dm_packet_alert_msg,
	NULL,
	handle_dm_config_new_msg,
	NULL,
	handle_dm_stats_new_msg,
};

static struct nl_sock *nsd;
static int nsf;

enum {
	STATE_IDLE = 0,
	STATE_ACTIVATING,
	STATE_RECEIVING,
	STATE_RQST_DEACTIVATE,
	STATE_RQST_ACTIVATE,
	STATE_DEACTIVATING,
	STATE_FAILED,
	STATE_EXIT,
	STATE_RQST_ALERT_MODE_SUMMARY,
	STATE_RQST_ALERT_MODE_PACKET,
	STATE_ALERT_MODE_SETTING,
	STATE_RQST_TRUNC_LEN,
	STATE_TRUNC_LEN_SETTING,
	STATE_RQST_QUEUE_LEN,
	STATE_QUEUE_LEN_SETTING,
	STATE_RQST_CONFIG,
	STATE_CONFIG_GETTING,
	STATE_RQST_STATS,
	STATE_STATS_GETTING,
};

static int state = STATE_IDLE;

static struct nla_policy net_dm_policy[NET_DM_ATTR_MAX + 1] = {
	[NET_DM_ATTR_ALERT_MODE]		= { .type = NLA_U8 },
	[NET_DM_ATTR_PC]			= { .type = NLA_U64 },
	[NET_DM_ATTR_SYMBOL]			= { .type = NLA_STRING },
	[NET_DM_ATTR_IN_PORT]			= { .type = NLA_NESTED },
	[NET_DM_ATTR_TIMESTAMP]			= { .type = NLA_U64 },
	[NET_DM_ATTR_PROTO]			= { .type = NLA_U16 },
	[NET_DM_ATTR_PAYLOAD]			= { .type = NLA_UNSPEC },
	[NET_DM_ATTR_TRUNC_LEN]			= { .type = NLA_U32 },
	[NET_DM_ATTR_ORIG_LEN]			= { .type = NLA_U32 },
	[NET_DM_ATTR_QUEUE_LEN]			= { .type = NLA_U32 },
	[NET_DM_ATTR_STATS]			= { .type = NLA_NESTED },
	[NET_DM_ATTR_HW_STATS]			= { .type = NLA_NESTED },
	[NET_DM_ATTR_ORIGIN]			= { .type = NLA_U16 },
	[NET_DM_ATTR_HW_TRAP_GROUP_NAME]	= { .type = NLA_STRING },
	[NET_DM_ATTR_HW_TRAP_NAME]		= { .type = NLA_STRING },
	[NET_DM_ATTR_HW_ENTRIES]		= { .type = NLA_NESTED },
	[NET_DM_ATTR_HW_ENTRY]			= { .type = NLA_NESTED },
	[NET_DM_ATTR_HW_TRAP_COUNT]		= { .type = NLA_U32 },
};

static struct nla_policy net_dm_port_policy[NET_DM_ATTR_PORT_MAX + 1] = {
	[NET_DM_ATTR_PORT_NETDEV_IFINDEX]	= { .type = NLA_U32 },
	[NET_DM_ATTR_PORT_NETDEV_NAME]		= { .type = NLA_STRING },
};

static struct nla_policy net_dm_stats_policy[NET_DM_ATTR_STATS_MAX + 1] = {
	[NET_DM_ATTR_STATS_DROPPED]		= { .type = NLA_U64 },
};

int strtobool(const char *str, bool *p_val)
{
	bool val;

	if (!strcmp(str, "true") || !strcmp(str, "1"))
		val = true;
	else if (!strcmp(str, "false") || !strcmp(str, "0"))
		val = false;
	else
		return -EINVAL;
	*p_val = val;
	return 0;
}

void sigint_handler(int signum)
{
	if ((state == STATE_RECEIVING) ||
	   (state == STATE_RQST_DEACTIVATE)) {
		disable_drop_monitor();
		state = STATE_DEACTIVATING;
	} else {
		printf("Got a sigint while not receiving\n");
	}
	return;
}

struct nl_sock *setup_netlink_socket()
{
	struct nl_sock *sd;
	int family;

	sd = nl_socket_alloc();

	genl_connect(sd);

	family = genl_ctrl_resolve(sd, "NET_DM");

	if (family < 0) {
		printf("Unable to find NET_DM family, dropwatch can't work\n");
		goto out_close;
	}

	nsf = family;

	nl_close(sd);
	nl_socket_free(sd);

	sd = nl_socket_alloc();
	nl_join_groups(sd, NET_DM_GRP_ALERT);

	nl_connect(sd, NETLINK_GENERIC);

	return sd;

out_close:
	nl_close(sd);
	nl_socket_free(sd);
	return NULL;
}

struct netlink_message *alloc_netlink_msg(uint32_t type, uint16_t flags, size_t size)
{
	struct netlink_message *msg;
	static uint32_t seq = 0;

	msg = (struct netlink_message *)malloc(sizeof(struct netlink_message));

	if (!msg)
		return NULL;

	msg->refcnt = 1;
	msg->nlbuf = nlmsg_alloc();
	msg->msg = genlmsg_put(msg->nlbuf, 0, seq, nsf, size, flags, type, 1);

	msg->ack_cb = NULL;
	msg->seq = seq++;

	return msg;
}

void set_ack_cb(struct netlink_message *msg,
			void (*cb)(struct netlink_message *, struct netlink_message *, int))
{
	if (msg->ack_cb)
		return;

	msg->ack_cb = cb;
	msg->refcnt++;
	LIST_INSERT_HEAD(&ack_list_head, msg, ack_list_element);
}

struct netlink_message *wrap_netlink_msg(struct nlmsghdr *buf)
{
	struct netlink_message *msg;

	msg = (struct netlink_message *)malloc(sizeof(struct netlink_message));
	if (msg) {
		msg->refcnt = 1;
		msg->msg = buf;
		msg->nlbuf = NULL;
	}

	return msg;
}

int free_netlink_msg(struct netlink_message *msg)
{
	int refcnt;

	msg->refcnt--;

	refcnt = msg->refcnt;

	if (!refcnt) {
		if (msg->nlbuf)
			nlmsg_free(msg->nlbuf);
		else
			free(msg->msg);
		free(msg);
	}

	return refcnt;
}

int send_netlink_message(struct netlink_message *msg)
{
	return nl_send(nsd, msg->nlbuf);
}

struct netlink_message *recv_netlink_message(int *err)
{
	static unsigned char *buf;
	struct netlink_message *msg;
	struct genlmsghdr *glm;
	struct sockaddr_nl nla;
	int type;
	int rc;

	*err = 0;

	do {
		rc = nl_recv(nsd, &nla, &buf, NULL);
		if (rc < 0) {
			switch (errno) {
			case EINTR:
				/*
				 * Take a pass throught the state loop
				 */
				return NULL;
				break;
			default:
				perror("Receive operation failed:");
				return NULL;
				break;
			}
		}
	} while (rc == 0);

	msg = wrap_netlink_msg((struct nlmsghdr *)buf);

	type = ((struct nlmsghdr *)msg->msg)->nlmsg_type;

	/*
	 * Note the NLMSG_ERROR is overloaded
	 * Its also used to deliver ACKs
	 */
	if (type == NLMSG_ERROR) {
		struct netlink_message *am;
		struct nlmsgerr *errm = nlmsg_data(msg->msg);
		LIST_FOREACH(am, &ack_list_head, ack_list_element) {
			if (am->seq == errm->msg.nlmsg_seq)
				break;
		}

		if (am) {
			LIST_REMOVE(am, ack_list_element);
			am->ack_cb(msg, am, errm->error);
			free_netlink_msg(am);
		} else {
			printf("Got an unexpected ack for sequence %d\n", errm->msg.nlmsg_seq);
		}

		free_netlink_msg(msg);
		return NULL;
	}

	glm = nlmsg_data(msg->msg);
	type = glm->cmd;

	if ((type > NET_DM_CMD_MAX) ||
	    (type <= NET_DM_CMD_UNSPEC)) {
		printf("Received message of unknown type %d\n",
			type);
		free_netlink_msg(msg);
		return NULL;
	}

	return msg;
}

void process_rx_message(void)
{
	struct netlink_message *msg;
	int err;
	int type;
	sigset_t bs;

	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);
	msg = recv_netlink_message(&err);
	sigprocmask(SIG_BLOCK, &bs, NULL);

	if (msg) {
		struct nlmsghdr *nlh = msg->msg;
		struct genlmsghdr *glh = nlmsg_data(nlh);
		type = glh->cmd;
		type_cb[type](msg, err);
	}
	return;
}

void print_nested_hw_entry(struct nlattr *hw_entry)
{
	struct nlattr *attrs[NET_DM_ATTR_MAX + 1];
	int err;

	err = nla_parse_nested(attrs, NET_DM_ATTR_MAX, hw_entry, net_dm_policy);
	if (err)
		return;

	if (!attrs[NET_DM_ATTR_HW_TRAP_NAME] ||
	    !attrs[NET_DM_ATTR_HW_TRAP_COUNT])
		return;

	printf("%d drops at %s [hardware]\n",
	       nla_get_u32(attrs[NET_DM_ATTR_HW_TRAP_COUNT]),
	       nla_get_string(attrs[NET_DM_ATTR_HW_TRAP_NAME]));
}

void print_nested_hw_entries(struct nlattr *hw_entries)
{
	struct nlattr *attr;
	int rem;

	nla_for_each_nested(attr, hw_entries, rem) {
		if (nla_type(attr) != NET_DM_ATTR_HW_ENTRY)
			continue;
		print_nested_hw_entry(attr);

		acount++;
		if (alimit && (acount == alimit)) {
			printf("Alert limit reached, deactivating!\n");
			state = STATE_RQST_DEACTIVATE;
		}
	}
}

/*
 * These are the received message handlers
 */
void handle_dm_alert_msg(struct netlink_message *msg, int err)
{
	int i;
	struct nlmsghdr *nlh = msg->msg;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct loc_result res;
	struct net_dm_alert_msg *alert = nla_data(genlmsg_data(glh));
	struct nlattr *attrs[NET_DM_ATTR_MAX + 1];

	if (state != STATE_RECEIVING)
		goto out_free;

	err = genlmsg_parse(msg->msg, 0, attrs, NET_DM_ATTR_MAX, net_dm_policy);
	if (err)
		goto out_free;

	for (i=0; i < alert->entries; i++) {
		void *location;
		memcpy(&location, alert->points[i].pc, sizeof(void *));
		if (lookup_symbol(location, &res))
			printf ("%d drops at location %p [software]\n", alert->points[i].count, location);
		else
			printf ("%d drops at %s+%llx (%p) [software]\n",
				alert->points[i].count, res.symbol, (unsigned long long)res.offset, location);
		acount++;
		if (alimit && (acount == alimit)) {
			printf("Alert limit reached, deactivating!\n");
			state = STATE_RQST_DEACTIVATE;
		}
	}

	if (attrs[NET_DM_ATTR_HW_ENTRIES])
		print_nested_hw_entries(attrs[NET_DM_ATTR_HW_ENTRIES]);

out_free:
	free_netlink_msg(msg);
}

void print_nested_port(struct nlattr *attr, const char *dir)
{
	struct nlattr *attrs[NET_DM_ATTR_PORT_MAX + 1];
	int err;

	err = nla_parse_nested(attrs, NET_DM_ATTR_PORT_MAX, attr,
			       net_dm_port_policy);
	if (err)
		return;

	if (attrs[NET_DM_ATTR_PORT_NETDEV_IFINDEX])
		printf("%s port ifindex: %d\n", dir,
		       nla_get_u32(attrs[NET_DM_ATTR_PORT_NETDEV_IFINDEX]));

	if (attrs[NET_DM_ATTR_PORT_NETDEV_NAME])
		printf("%s port name: %s\n", dir,
		       nla_get_string(attrs[NET_DM_ATTR_PORT_NETDEV_NAME]));
}

void print_packet_origin(struct nlattr *attr)
{
	const char *origin;
	uint16_t val;

	val = nla_get_u16(attr);
	switch (val) {
	case NET_DM_ORIGIN_SW:
		origin = "software";
		break;
	case NET_DM_ORIGIN_HW:
		origin = "hardware";
		break;
	default:
		origin = "unknown";
		break;
	}

	printf("origin: %s\n", origin);
}

void handle_dm_packet_alert_msg(struct netlink_message *msg, int err)
{
	struct nlattr *attrs[NET_DM_ATTR_MAX + 1];

	if (state != STATE_RECEIVING)
		goto out_free;

	err = genlmsg_parse(msg->msg, 0, attrs, NET_DM_ATTR_MAX, net_dm_policy);
	if (err)
		goto out_free;

	if (attrs[NET_DM_ATTR_PC] && attrs[NET_DM_ATTR_SYMBOL])
		printf("drop at: %s (0x%llx)\n",
		       nla_get_string(attrs[NET_DM_ATTR_SYMBOL]),
		       (long long unsigned int)nla_get_u64(attrs[NET_DM_ATTR_PC]));
	else if (attrs[NET_DM_ATTR_HW_TRAP_GROUP_NAME] &&
		 attrs[NET_DM_ATTR_HW_TRAP_NAME])
		printf("drop at: %s (%s)\n",
		       nla_get_string(attrs[NET_DM_ATTR_HW_TRAP_NAME]),
		       nla_get_string(attrs[NET_DM_ATTR_HW_TRAP_GROUP_NAME]));

	if (attrs[NET_DM_ATTR_ORIGIN])
		print_packet_origin(attrs[NET_DM_ATTR_ORIGIN]);

	if (attrs[NET_DM_ATTR_IN_PORT])
		print_nested_port(attrs[NET_DM_ATTR_IN_PORT], "input");

	if (attrs[NET_DM_ATTR_TIMESTAMP]) {
		time_t tv_sec;
		struct tm *tm;
		uint64_t ts;
		char *tstr;

		ts = nla_get_u64(attrs[NET_DM_ATTR_TIMESTAMP]);
		tv_sec = ts / 1000000000;
		tm = localtime(&tv_sec);

		tstr = asctime(tm);
		tstr[strlen(tstr) - 1] = 0;
		printf("timestamp: %s %09lld nsec\n", tstr, (long long unsigned int)ts % 1000000000);
	}

	if (attrs[NET_DM_ATTR_PROTO])
		printf("protocol: 0x%x\n",
		       nla_get_u16(attrs[NET_DM_ATTR_PROTO]));

	if (attrs[NET_DM_ATTR_PAYLOAD])
		printf("length: %u\n", nla_len(attrs[NET_DM_ATTR_PAYLOAD]));

	if (attrs[NET_DM_ATTR_ORIG_LEN])
		printf("original length: %u\n",
		       nla_get_u32(attrs[NET_DM_ATTR_ORIG_LEN]));

	printf("\n");

	acount++;
	if (alimit && (acount == alimit)) {
		printf("Alert limit reached, deactivating!\n");
		state = STATE_RQST_DEACTIVATE;
	}

out_free:
	free_netlink_msg(msg);
}

void handle_dm_config_new_msg(struct netlink_message *msg, int err)
{
	struct nlattr *attrs[NET_DM_ATTR_MAX + 1];

	if (state != STATE_CONFIG_GETTING)
		goto out_free;

	err = genlmsg_parse(msg->msg, 0, attrs, NET_DM_ATTR_MAX, net_dm_policy);
	if (err)
		goto out_free;

	if (!attrs[NET_DM_ATTR_ALERT_MODE] || !attrs[NET_DM_ATTR_TRUNC_LEN] ||
	    !attrs[NET_DM_ATTR_QUEUE_LEN])
		goto out_free;

	printf("Alert mode: ");
	switch (nla_get_u8(attrs[NET_DM_ATTR_ALERT_MODE])) {
	case NET_DM_ALERT_MODE_SUMMARY:
		printf("Summary\n");
		break;
	case NET_DM_ALERT_MODE_PACKET:
		printf("Packet\n");
		break;
	default:
		printf("Invalid alert mode\n");
		break;
	}

	printf("Truncation length: %u\n",
	       nla_get_u32(attrs[NET_DM_ATTR_TRUNC_LEN]));

	printf("Queue length: %u\n", nla_get_u32(attrs[NET_DM_ATTR_QUEUE_LEN]));

out_free:
	state = STATE_IDLE;
	free_netlink_msg(msg);
}

void print_nested_stats(struct nlattr *attr)
{
	struct nlattr *attrs[NET_DM_ATTR_STATS_MAX + 1];
	int err;

	err = nla_parse_nested(attrs, NET_DM_ATTR_STATS_MAX, attr,
			       net_dm_stats_policy);
	if (err)
		return;

	if (attrs[NET_DM_ATTR_STATS_DROPPED])
		printf("Tail dropped: %llu\n",
		       (long long unsigned int)nla_get_u64(attrs[NET_DM_ATTR_STATS_DROPPED]));
}

void handle_dm_stats_new_msg(struct netlink_message *msg, int err)
{
	struct nlattr *attrs[NET_DM_ATTR_MAX + 1];

	if (state != STATE_STATS_GETTING)
		goto out_free;

	err = genlmsg_parse(msg->msg, 0, attrs, NET_DM_ATTR_MAX, net_dm_policy);
	if (err)
		goto out_free;

	if (attrs[NET_DM_ATTR_STATS]) {
		printf("Software statistics:\n");
		print_nested_stats(attrs[NET_DM_ATTR_STATS]);
	}

	if (attrs[NET_DM_ATTR_HW_STATS]) {
		printf("Hardware statistics:\n");
		print_nested_stats(attrs[NET_DM_ATTR_HW_STATS]);
	}

out_free:
	state = STATE_IDLE;
	free_netlink_msg(msg);
}

void handle_dm_config_msg(struct netlink_message *amsg, struct netlink_message *msg, int err)
{
	if (err != 0) {
		char *erm = strerror(-err);

		printf("Failed config request, error: %s\n", erm);
		state = STATE_FAILED;
		return;
	}

	switch (state) {
	case STATE_ALERT_MODE_SETTING:
		printf("Alert mode successfully set\n");
		state = STATE_IDLE;
		break;
	case STATE_TRUNC_LEN_SETTING:
		printf("Truncation length successfully set\n");
		state = STATE_IDLE;
		break;
	case STATE_QUEUE_LEN_SETTING:
		printf("Queue length successfully set\n");
		state = STATE_IDLE;
		break;
	default:
		printf("Received acknowledgement for non-solicited config request\n");
		state = STATE_FAILED;
	}
}

void handle_dm_start_msg(struct netlink_message *amsg, struct netlink_message *msg, int err)
{
	if (err != 0) {
		char *erm = strerror(err*-1);
		printf("Failed activation request, error: %s\n", erm);
		state = STATE_FAILED;
		goto out;
	}

	if (state == STATE_ACTIVATING) {
		struct sigaction act;
		memset(&act, 0, sizeof(struct sigaction));
		act.sa_handler = sigint_handler;
		act.sa_flags = SA_RESETHAND;

		printf("Kernel monitoring activated.\n");
		printf("Issue Ctrl-C to stop monitoring\n");
		sigaction(SIGINT, &act, NULL);

		state = STATE_RECEIVING;
	} else {
		printf("Odd, the kernel told us that it activated and we didn't ask\n");
		state = STATE_FAILED;
	}
out:
	return;
}

void handle_dm_stop_msg(struct netlink_message *amsg, struct netlink_message *msg, int err)
{
	char *erm;

	if ((err == 0) || (err == -EAGAIN)) {
		printf("Got a stop message\n");
		state = STATE_IDLE;
	} else {
		erm = strerror(err*-1);
		printf("Stop request failed, error: %s\n", erm);
	}
}

int enable_drop_monitor()
{
	struct netlink_message *msg;

	msg = alloc_netlink_msg(NET_DM_CMD_START, NLM_F_REQUEST|NLM_F_ACK, 0);

	if (monitor_sw && nla_put_flag(msg->nlbuf, NET_DM_ATTR_SW_DROPS))
		goto nla_put_failure;

	if (monitor_hw && nla_put_flag(msg->nlbuf, NET_DM_ATTR_HW_DROPS))
		goto nla_put_failure;

	set_ack_cb(msg, handle_dm_start_msg);

	return send_netlink_message(msg);

nla_put_failure:
	free_netlink_msg(msg);
	return -EMSGSIZE;
}

int disable_drop_monitor()
{
	struct netlink_message *msg;

	msg = alloc_netlink_msg(NET_DM_CMD_STOP, NLM_F_REQUEST|NLM_F_ACK, 0);

	if (monitor_sw && nla_put_flag(msg->nlbuf, NET_DM_ATTR_SW_DROPS))
		goto nla_put_failure;

	if (monitor_hw && nla_put_flag(msg->nlbuf, NET_DM_ATTR_HW_DROPS))
		goto nla_put_failure;

	set_ack_cb(msg, handle_dm_stop_msg);

	return send_netlink_message(msg);

nla_put_failure:
	free_netlink_msg(msg);
	return -EMSGSIZE;
}

int set_alert_mode()
{
	enum net_dm_alert_mode alert_mode;
	struct netlink_message *msg;

	switch (state) {
	case STATE_RQST_ALERT_MODE_SUMMARY:
		alert_mode = NET_DM_ALERT_MODE_SUMMARY;
		break;
	case STATE_RQST_ALERT_MODE_PACKET:
		alert_mode = NET_DM_ALERT_MODE_PACKET;
		break;
	default:
		return -EINVAL;
	}

	msg = alloc_netlink_msg(NET_DM_CMD_CONFIG, NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!msg)
		return -ENOMEM;

	if (nla_put_u8(msg->nlbuf, NET_DM_ATTR_ALERT_MODE, alert_mode))
		goto nla_put_failure;

	set_ack_cb(msg, handle_dm_config_msg);

	return send_netlink_message(msg);

nla_put_failure:
	free_netlink_msg(msg);
	return -EMSGSIZE;
}

int set_trunc_len()
{
	struct netlink_message *msg;

	msg = alloc_netlink_msg(NET_DM_CMD_CONFIG, NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!msg)
		return -ENOMEM;

	if (nla_put_u32(msg->nlbuf, NET_DM_ATTR_TRUNC_LEN, trunc_len))
		goto nla_put_failure;

	set_ack_cb(msg, handle_dm_config_msg);

	return send_netlink_message(msg);

nla_put_failure:
	free_netlink_msg(msg);
	return -EMSGSIZE;
}

int set_queue_len()
{
	struct netlink_message *msg;

	msg = alloc_netlink_msg(NET_DM_CMD_CONFIG, NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!msg)
		return -ENOMEM;

	if (nla_put_u32(msg->nlbuf, NET_DM_ATTR_QUEUE_LEN, queue_len))
		goto nla_put_failure;

	set_ack_cb(msg, handle_dm_config_msg);

	return send_netlink_message(msg);

nla_put_failure:
	free_netlink_msg(msg);
	return -EMSGSIZE;
}

int get_config()
{
	struct netlink_message *msg;

	msg = alloc_netlink_msg(NET_DM_CMD_CONFIG_GET, NLM_F_REQUEST, 0);
	if (!msg)
		return -ENOMEM;

	return send_netlink_message(msg);
}

int get_stats()
{
	struct netlink_message *msg;

	msg = alloc_netlink_msg(NET_DM_CMD_STATS_GET, NLM_F_REQUEST, 0);
	if (!msg)
		return -ENOMEM;

	return send_netlink_message(msg);
}

void display_help()
{
	printf("Command Syntax:\n");
	printf("exit\t\t\t\t - Quit dropwatch\n");
	printf("help\t\t\t\t - Display this message\n");
	printf("set:\n");
	printf("\talertlimit <number>\t - caputre only this many alert packets\n");
	printf("\talertmode <mode>\t - set mode to \"summary\" or \"packet\"\n");
	printf("\ttrunc <len>\t\t - truncate packets to this length. ");
	printf("Only applicable when \"alertmode\" is set to \"packet\"\n");
	printf("\tqueue <len>\t\t - queue up to this many packets in the kernel. ");
	printf("Only applicable when \"alertmode\" is set to \"packet\"\n");
	printf("\tsw <true | false>\t - monitor software drops\n");
	printf("\thw <true | false>\t - monitor hardware drops\n");
	printf("start\t\t\t\t - start capture\n");
	printf("stop\t\t\t\t - stop capture\n");
	printf("show\t\t\t\t - show existing configuration\n");
	printf("stats\t\t\t\t - show statistics\n");
}

void enter_command_line_mode()
{
	char *input;
	int err;

	do {
		input = readline("dropwatch> ");

		if (input == NULL) {
			/* Someone closed stdin on us */
			printf("Terminating dropwatch...\n");
			state = STATE_EXIT;
			break;
		}

		if (!strcmp(input,"start")) {
			state = STATE_RQST_ACTIVATE;
			break;
		}

		if (!strcmp(input, "stop")) {
			state = STATE_RQST_DEACTIVATE;
			break;
		}

		if (!strcmp(input, "exit")) {
			state = STATE_EXIT;
			break;
		}

		if (!strcmp (input, "help")) {
			display_help();
			goto next_input;
		}

		if (!strncmp(input, "set", 3)) {
			char *ninput = input+4;
			if (!strncmp(ninput, "alertlimit", 10)) {
				alimit = strtoul(ninput+10, NULL, 10);
				printf("setting alert capture limit to %lu\n",
					alimit);
				goto next_input;
			} else if (!strncmp(ninput, "alertmode", 9)) {
				ninput = ninput + 10;
				if (!strncmp(ninput, "summary", 7)) {
					state = STATE_RQST_ALERT_MODE_SUMMARY;
					break;
				} else if (!strncmp(ninput, "packet", 6)) {
					state = STATE_RQST_ALERT_MODE_PACKET;
					break;
				}
			} else if (!strncmp(ninput, "trunc", 5)) {
				trunc_len = strtoul(ninput + 6, NULL, 10);
				state = STATE_RQST_TRUNC_LEN;
				break;
			} else if (!strncmp(ninput, "queue", 5)) {
				queue_len = strtoul(ninput + 6, NULL, 10);
				state = STATE_RQST_QUEUE_LEN;
				break;
			} else if (!strncmp(ninput, "sw", 2)) {
				err = strtobool(ninput + 3, &monitor_sw);
				if (err) {
					printf("invalid boolean value\n");
					state = STATE_FAILED;
					break;
				}
				printf("setting software drops monitoring to %d\n",
				       monitor_sw);
				goto next_input;
			} else if (!strncmp(ninput, "hw", 2)) {
				err = strtobool(ninput + 3, &monitor_hw);
				if (err) {
					printf("invalid boolean value\n");
					state = STATE_FAILED;
					break;
				}
				printf("setting hardware drops monitoring to %d\n",
				       monitor_hw);
				goto next_input;
			}
		}

		if (!strncmp(input, "show", 4)) {
			state = STATE_RQST_CONFIG;
			break;
		}

		if (!strncmp(input, "stats", 5)) {
			state = STATE_RQST_STATS;
			break;
		}
next_input:
		free(input);
	} while(1);

	free(input);
}

void enter_state_loop(void)
{
	int should_rx = 0;

	while (1) {
		switch(state) {

		case STATE_IDLE:
			should_rx = 0;
			enter_command_line_mode();
			break;
		case STATE_RQST_ACTIVATE:
			printf("Enabling monitoring...\n");
			if (enable_drop_monitor() < 0) {
				perror("Unable to send activation msg:");
				state = STATE_FAILED;
			} else {
				state = STATE_ACTIVATING;
				should_rx = 1;
			}
			break;
		case STATE_ACTIVATING:
			printf("Waiting for activation ack....\n");
			break;
		case STATE_RECEIVING:
			break;
		case STATE_RQST_DEACTIVATE:
			printf("Deactivation requested, turning off monitoring\n");
			if (disable_drop_monitor() < 0) {
				perror("Unable to send deactivation msg:");
				state = STATE_FAILED;
			} else
				state = STATE_DEACTIVATING;
			should_rx = 1;
			break;
		case STATE_DEACTIVATING:
			printf("Waiting for deactivation ack...\n");
			break;
		case STATE_EXIT:
		case STATE_FAILED:
			should_rx = 0;
			return;
		case STATE_RQST_ALERT_MODE_SUMMARY:
		case STATE_RQST_ALERT_MODE_PACKET:
			printf("Setting alert mode\n");
			if (set_alert_mode() < 0) {
				perror("Failed to set alert mode");
				state = STATE_FAILED;
			} else {
				state = STATE_ALERT_MODE_SETTING;
				should_rx = 1;
			}
			break;
		case STATE_ALERT_MODE_SETTING:
			printf("Waiting for alert mode setting ack...\n");
			break;
		case STATE_RQST_TRUNC_LEN:
			printf("Setting truncation length to %lu\n",
			       trunc_len);
			if (set_trunc_len() < 0) {
				perror("Failed to set truncation length");
				state = STATE_FAILED;
			} else {
				state = STATE_TRUNC_LEN_SETTING;
				should_rx = 1;
			}
			break;
		case STATE_TRUNC_LEN_SETTING:
			printf("Waiting for truncation length setting ack...\n");
			break;
		case STATE_RQST_QUEUE_LEN:
			printf("Setting queue length to %lu\n", queue_len);
			if (set_queue_len() < 0) {
				perror("Failed to set queue length");
				state = STATE_FAILED;
			} else {
				state = STATE_QUEUE_LEN_SETTING;
				should_rx = 1;
			}
			break;
		case STATE_QUEUE_LEN_SETTING:
			printf("Waiting for queue length setting ack...\n");
			break;
		case STATE_RQST_CONFIG:
			printf("Getting existing configuration\n");
			if (get_config() < 0) {
				perror("Failed to get existing configuration");
				state = STATE_FAILED;
			} else {
				state = STATE_CONFIG_GETTING;
				should_rx = 1;
			}
			break;
		case STATE_CONFIG_GETTING:
			printf("Waiting for existing configuration query response\n");
			break;
		case STATE_RQST_STATS:
			printf("Getting statistics\n");
			if (get_stats() < 0) {
				perror("Failed to get statistics");
				state = STATE_FAILED;
			} else {
				state = STATE_STATS_GETTING;
				should_rx = 1;
			}
			break;
		case STATE_STATS_GETTING:
			printf("Waiting for statistics query response\n");
			break;
		default:
			printf("Unknown state received!  exiting!\n");
			state = STATE_FAILED;
			should_rx = 0;
			break;
		}

		/*
		 * After we process our state loop, look to see if we have messages
		 */
		if (should_rx)
			process_rx_message();
	}
}

struct option options[] = {
	{"lmethod", 1, 0, 'l'},
	{0, 0, 0, 0}
};

void usage()
{
	printf("dropwatch [-l|--lmethod <method | list>]\n");
}

int main (int argc, char **argv)
{
	int c, optind;
	lookup_init_method_t meth = METHOD_NULL;
	/*
	 * parse the options
	 */
	for(;;) {
		c = getopt_long(argc, argv, "l:", options, &optind);

		/* are we done parsing ? */
		if (c == -1)
			break;

		switch(c) {

		case '?':
			usage();
			exit(1);
			/* NOTREACHED */
		case 'l':
			/* select the lookup method we want to use */
			if (!strncmp(optarg, "list", 4)) {
				printf("Available lookup methods:\n");
				printf("kas - use /proc/kallsyms\n");
				exit(0);
			} else if (!strncmp(optarg, "kas", 3)) {
				meth = METHOD_KALLSYMS;
			} else {
				printf("Unknown lookup method %s\n", optarg);
				exit(1);
			}
			break;
		default:
			printf("Unknown option\n");
			usage();
			exit(1);
			/* NOTREACHED */
		}
	}

	/*
	 * open up the netlink socket that we need to talk to our dropwatch socket
	 */
	nsd = setup_netlink_socket();

	if (nsd == NULL) {
		printf("Cleaning up on socket creation error\n");
		goto out;
	}


	/*
 	 * Initalize our lookup library
 	 */
	init_lookup(meth);

	enter_state_loop();
	printf("Shutting down ...\n");

	nl_close(nsd);
	exit(0);
out:
	exit(1);
}
