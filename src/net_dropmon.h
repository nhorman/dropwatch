#ifndef __NET_DROPMON_H
#define __NET_DROPMON_H

#include <linux/netlink.h>

struct net_dm_drop_point {
	uint8_t pc[8];
	uint32_t count;
};

#define NET_DM_CFG_VERSION  0
#define NET_DM_CFG_ALERT_COUNT  1
#define NET_DM_CFG_ALERT_DELAY 2
#define NET_DM_CFG_MAX 3

struct net_dm_config_entry {
	uint32_t type;
	uint64_t  data __attribute__((aligned(8)));
};

struct net_dm_config_msg {
	uint32_t entries;
	struct net_dm_config_entry options[0];
};

struct net_dm_alert_msg {
	uint32_t entries;
	struct net_dm_drop_point points[0];
};

struct net_dm_user_msg {
	union {
		struct net_dm_config_msg user;
		struct net_dm_alert_msg alert;
	}u;
};


/* These are the netlink message types for this protocol */

enum {
	NET_DM_CMD_UNSPEC = 0,
	NET_DM_CMD_ALERT,
	NET_DM_CMD_CONFIG,
	NET_DM_CMD_START,
	NET_DM_CMD_STOP,
	_NET_DM_CMD_MAX,
};

#define NET_DM_CMD_MAX (_NET_DM_CMD_MAX - 1)

/*
 * Our group identifiers
 */
#define NET_DM_GRP_ALERT 1
#endif
