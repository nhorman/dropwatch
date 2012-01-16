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

void handle_dm_alert_msg(struct netlink_message *msg, int err);
void handle_dm_config_msg(struct netlink_message *msg, int err);
void handle_dm_start_msg(struct netlink_message *amsg, struct netlink_message *msg, int err);
void handle_dm_stop_msg(struct netlink_message *amsg, struct netlink_message *msg, int err);
int disable_drop_monitor();


static void(*type_cb[_NET_DM_CMD_MAX])(struct netlink_message *, int err) = {
	NULL,
	handle_dm_alert_msg,
	handle_dm_config_msg,
	NULL,
	NULL
};

static struct nl_handle *nsd;
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
};

static int state = STATE_IDLE;

void sigint_handler(int signum)
{
	if ((state == STATE_RECEIVING) ||
	   (state == STATE_RQST_DEACTIVATE)) {
		disable_drop_monitor();
		state = STATE_DEACTIVATING;
	}
	else
		printf("Got a sigint while not receiving\n");
	return;	
}

struct nl_handle *setup_netlink_socket()
{
	struct nl_handle *sd;
	int family;

	
	sd = nl_handle_alloc();

	genl_connect(sd);

	family = genl_ctrl_resolve(sd, "NET_DM");

	if (family < 0) {
		printf("Unable to find NET_DM family, dropwatch can't work\n");
		goto out_close;
	}

	nsf = family;

	nl_close(sd);
	nl_handle_destroy(sd);

	sd = nl_handle_alloc();
	nl_join_groups(sd, NET_DM_GRP_ALERT);

	nl_connect(sd, NETLINK_GENERIC);

	return sd;

out_close:
	nl_close(sd);
	nl_handle_destroy(sd);
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
		type  = glh->cmd; 
		type_cb[type](msg, err);
	}
	return;
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

	if (state != STATE_RECEIVING)
		goto out_free;



	for (i=0; i < alert->entries; i++) {
		void *location;
		memcpy(&location, alert->points[i].pc, sizeof(void *));
		if (lookup_symbol(location, &res))
			printf ("%d drops at location %p\n", alert->points[i].count, location);
		else
			printf ("%d drops at %s+%llx (%p)\n",
				alert->points[i].count, res.symbol, res.offset, location);
		acount++;
		if (alimit && (acount == alimit)) {
			printf("Alert limit reached, deactivating!\n");
			state = STATE_RQST_DEACTIVATE;
		}
	}	

out_free:
	free_netlink_msg(msg);
}

void handle_dm_config_msg(struct netlink_message *msg, int err)
{
	printf("Got a config message\n");
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

	set_ack_cb(msg, handle_dm_start_msg);
	
	return send_netlink_message(msg);
}

int disable_drop_monitor()
{
	struct netlink_message *msg;

	msg = alloc_netlink_msg(NET_DM_CMD_STOP, NLM_F_REQUEST|NLM_F_ACK, 0);

	set_ack_cb(msg, handle_dm_stop_msg);

	return send_netlink_message(msg);
}

void display_help()
{
	printf("Command Syntax:\n");
	printf("exit\t\t\t\t - Quit dropwatch\n");
	printf("help\t\t\t\t - Display this message\n");
	printf("set:\n");
	printf("\talertlimit <number>\t - caputre only this many alert packets\n");
	printf("start\t\t\t\t - start capture\n");
	printf("stop\t\t\t\t - stop capture\n");
}

void enter_command_line_mode()
{
	char *input;

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
			}
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
