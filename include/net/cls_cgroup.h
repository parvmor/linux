/*
 * cls_cgroup.h			Control Group Classifier
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#ifndef _NET_CLS_CGROUP_H
#define _NET_CLS_CGROUP_H

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/cgroup.h>
#include <linux/hardirq.h>
#include <linux/rcupdate.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#ifdef CONFIG_CGROUP_NET_CLASSID
struct counter_t {
	atomic_long_t usage;
	struct counter_t *parent;
};

static inline void counter_init(struct counter_t *counter,
				struct counter_t *parent)
{
	atomic_long_set(&counter->usage, 0);
	counter->parent = parent;
}

static inline unsigned long counter_read(struct counter_t *counter)
{
	return atomic_long_read(&counter->usage);
}

struct cgroup_cls_state {
	struct cgroup_subsys_state css;
	u32 classid;
	/* Accounts for both data and ack segments */
	struct counter_t tcp_packets_sent;
	struct counter_t tcp_packets_rcvd;
	struct counter_t udp_packets_sent;
	struct counter_t udp_packets_rcvd;
	/* Accounts only for data segments */
	struct counter_t tcp_total_segment_size;
	struct counter_t tcp_total_segments;
};

struct cgroup_cls_state *task_cls_state(struct task_struct *p);

static inline u32 task_cls_classid(struct task_struct *p)
{
	u32 classid;

	if (in_interrupt())
		return 0;

	rcu_read_lock();
	classid = container_of(task_css(p, net_cls_cgrp_id),
			       struct cgroup_cls_state, css)
			  ->classid;
	rcu_read_unlock();

	return classid;
}

static inline void sock_update_classid(struct sock_cgroup_data *skcd)
{
	u32 classid;

	classid = task_cls_classid(current);
	sock_cgroup_set_classid(skcd, classid);
}

static inline u32 task_get_classid(const struct sk_buff *skb)
{
	u32 classid = task_cls_state(current)->classid;

	/* Due to the nature of the classifier it is required to ignore all
	 * packets originating from softirq context as accessing `current'
	 * would lead to false results.
	 *
	 * This test assumes that all callers of dev_queue_xmit() explicitly
	 * disable bh. Knowing this, it is possible to detect softirq based
	 * calls by looking at the number of nested bh disable calls because
	 * softirqs always disables bh.
	 */
	if (in_serving_softirq()) {
		struct sock *sk = skb_to_full_sk(skb);

		/* If there is an sock_cgroup_classid we'll use that. */
		if (!sk || !sk_fullsock(sk))
			return 0;

		classid = sock_cgroup_classid(&sk->sk_cgrp_data);
	}

	return classid;
}
#else /* !CONFIG_CGROUP_NET_CLASSID */
static inline void sock_update_classid(struct sock_cgroup_data *skcd)
{
}

static inline u32 task_get_classid(const struct sk_buff *skb)
{
	return 0;
}
#endif /* CONFIG_CGROUP_NET_CLASSID */
#endif /* _NET_CLS_CGROUP_H */
