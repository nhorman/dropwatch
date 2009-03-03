#ifndef __NET_DROPMON_H
#define __NET_DROPMON_H

#include <linux/netlink.h>

struct net_dm_drop_point {
	uint8_t pc[8];
	uint32_t count;
};

typedef enum {
	NET_DM_CFG_VERSION = 0,
	NET_DM_CFG_ALERT_COUNT,
	NET_DM_CFG_ALERT_DELAY,
	NET_DM_CFG_MAX,
} config_type_t;

struct net_dm_config_entry {
	config_type_t type;
	uint64_t data;
};

struct net_dm_config_msg {
	size_t entries;
	struct net_dm_config_entry options[0];
};

struct net_dm_alert_msg {
	size_t entries;
	struct net_dm_drop_point points[0];
};

struct net_dm_user_msg {
	union {
		struct net_dm_config_msg user;
		struct net_dm_alert_msg alert;
	}u;
};

/*
 * Group names
 */
#define NET_DM_GRP_ALERTS 1


/* These are the netlink message types for this protocol */

#define NET_DM_BASE	0x10 			/* Standard Netlink Messages below this */
#define NET_DM_ALERT	(NET_DM_BASE + 1) 	/* Alert about dropped packets */
#define NET_DM_CONFIG	(NET_DM_BASE + 2)	/* Configuration message */
#define NET_DM_START	(NET_DM_BASE + 3)	/* Start monitoring */
#define NET_DM_STOP	(NET_DM_BASE + 4)	/* Stop monitoring */
#define NET_DM_MAX	(NET_DM_BASE + 5)
#endif
