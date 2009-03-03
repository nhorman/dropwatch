/*
 * Copyright (C) 2009, Neil Horman <nhorman@tuxdriver.com>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <asm/types.h>

#include "net_dropmon.h"

/*
 * This is just in place until the kernel changes get comitted
 */
#ifndef NETLINK_DRPMON
#define NETLINK_DRPMON 20
#endif

#define RX_BUF_SIZE 4096

struct netlink_message {
	struct nlmsghdr *msg;
	int refcnt;
};

void handle_dm_alert_msg(struct netlink_message *msg, int err);
void handle_dm_config_msg(struct netlink_message *msg, int err);
void handle_dm_start_msg(struct netlink_message *msg, int err);
void handle_dm_stop_msg(struct netlink_message *msg, int err);


static void(*type_cb[NET_DM_MAX])(struct netlink_message *, int err) = {
	NULL,
	handle_dm_alert_msg,
	handle_dm_config_msg,
	handle_dm_start_msg,
	handle_dm_stop_msg
};

static int nsd;

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
	   (state == STATE_RQST_DEACTIVATE))
		state = STATE_RQST_DEACTIVATE;
	else
		printf("Got a sigint while not receiving\n");
	return;	
}

int setup_netlink_socket()
{
	int sd;
	struct sockaddr_nl nls;

	sd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_DRPMON);

	if (sd < 0) {
		perror("Unable to open socket:");
		return sd;
	}

	/*
 	 * Bind us to the first group so that we get alert messages
 	 */
	memset(&nls, 0, sizeof(nls));
	nls.nl_family = AF_NETLINK;
	nls.nl_groups = NET_DM_GRP_ALERTS;

	if (bind(sd, (const struct sockaddr *)&nls, sizeof(struct sockaddr_nl)) < 0) {
		perror("Unable to bind to alerting group:");
		goto out_close;
	}

	return sd;

out_close:
	close(sd);
	return -1;

}

struct netlink_message *alloc_netlink_msg(uint32_t type, uint16_t flags, size_t size)
{
	struct netlink_message *msg;
	static uint32_t seq = 0;

	size += NLMSG_ALIGN(sizeof(struct netlink_message));
	size += sizeof(struct nlmsghdr);
	size = NLMSG_LENGTH(size);


	msg = (struct netlink_message *)malloc(size);

	if (!msg)
		return NULL;

	msg->refcnt = 1;
	msg->msg = (struct nlmsghdr *)((char *)msg+NLMSG_ALIGN(sizeof(struct netlink_message)));
	msg->msg->nlmsg_len = size;
	msg->msg->nlmsg_type = type;
	msg->msg->nlmsg_flags = flags;
	msg->msg->nlmsg_seq = seq++;
	msg->msg->nlmsg_pid = 0;

	return msg;
}

struct netlink_message *wrap_netlink_msg(struct nlmsghdr *buf)
{
	struct netlink_message *msg;

	msg = (struct netlink_message *)malloc(sizeof(struct netlink_message));
	if (msg) {
		msg->refcnt = 1;
		msg->msg = buf;
	}

	return msg;
}

int free_netlink_msg(struct netlink_message *msg)
{
	int refcnt;

	msg->refcnt--;

	refcnt = msg->refcnt;

	if (!refcnt)
		free(msg);

	return refcnt;
}

int send_netlink_message(struct netlink_message *msg)
{
	return send(nsd, msg->msg, msg->msg->nlmsg_len, 0);
}

struct netlink_message *recv_netlink_message(int *err)
{
	static char buf[RX_BUF_SIZE];
	struct netlink_message *msg;
	int type;
	int rc;

	*err = 0;
	printf("Trying to get a netlink msg\n");
	do {
		rc = recv(nsd, buf, RX_BUF_SIZE, 0);
		printf("Got a netlink message\n");
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

	type = msg->msg->nlmsg_type;

	/*
	 * Note the NLMSG_ERROR is overloaded
	 * Its also used to deliver ACKs
	 */
	if (type == NLMSG_ERROR) {
		struct nlmsgerr *ermsg;
		ermsg = NLMSG_DATA(msg->msg);
		msg->msg = &ermsg->msg;
		*err = ermsg->error;
		type = msg->msg->nlmsg_type;
	}
		
	if ((type >= NET_DM_MAX) ||
	    (type <= NET_DM_BASE)) {
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

	msg = recv_netlink_message(&err);

	if (msg)
		type_cb[msg->msg->nlmsg_type-NET_DM_BASE](msg, err);
	return;
}



/*
 * These are the received message handlers
 */
void handle_dm_alert_msg(struct netlink_message *msg, int err)
{
	int i;
	struct net_dm_alert_msg *alert = NLMSG_DATA(msg->msg);

	printf("Got Drop notifications\n");


	for (i=0; i < alert->entries; i++) {
		void *location;
		memcpy(&location, alert->points[i].pc, sizeof(void *));
		printf ("%d drops at location %p\n", alert->points[i].count, location);
	}	

	free_netlink_msg(msg);
}

void handle_dm_config_msg(struct netlink_message *msg, int err)
{
	printf("Got a config message\n");
}

void handle_dm_start_msg(struct netlink_message *msg, int err)
{
	if (err != 0) {
		printf("Failed activation request, error = %d\n", err);
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
	free_netlink_msg(msg);
	return;
}

void handle_dm_stop_msg(struct netlink_message *msg, int err)
{
	printf("Got a stop message\n");
	if (err == 0)
		state = STATE_IDLE;
}

int enable_drop_monitor()
{
	struct netlink_message *msg;

	msg = alloc_netlink_msg(NET_DM_START, NLM_F_REQUEST|NLM_F_ACK, 0);

	return send_netlink_message(msg);
}

int disable_drop_monitor()
{
	struct netlink_message *msg;
	msg = alloc_netlink_msg(NET_DM_STOP, NLM_F_REQUEST|NLM_F_ACK, 0);

	return send_netlink_message(msg);
}

void enter_command_line_mode()
{
	char *input;

	do {
		input = readline("dropwatch> ");

		if (!strcmp(input,"start")) {
			state = STATE_RQST_ACTIVATE;
			break;
		}

		if (!strcmp(input, "exit")) {
			state = STATE_EXIT;
			break;
		}

		free(input);
	} while(1);
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

int main (int argc, char **argv)
{

	/*
	 * open up the netlink socket that we need to talk to our dropwatch socket
	 */
	nsd = setup_netlink_socket();

	if (nsd < 1) {
		printf("Cleaning up on socket creation error\n");
		goto out;
	}


	enter_state_loop();
	printf("Shutting down ...\n");
	close(nsd);
	exit(0);
out:
	exit(1);
}
