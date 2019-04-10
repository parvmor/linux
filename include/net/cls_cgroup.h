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
extern atomic_long_t unknown;

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

static inline void counter_charge(struct counter_t *counter,
				  unsigned long value)
{
	struct counter_t *c;
	for (c = counter; c; c = c->parent) {
		atomic_long_add(value, &c->usage);
	}
}

struct rate_limit_t {
	atomic_long_t limit;
	struct rate_limit_t *parent;
};

static inline void rate_limit_init(struct rate_limit_t *rl,
				   struct rate_limit_t *parent)
{
	atomic_long_set(&rl->limit, LONG_MAX);
	rl->parent = parent;
}

static inline unsigned long rate_limit_read(struct rate_limit_t *rl)
{
	return atomic_long_read(&rl->limit);
}

static inline void rate_limit_set(struct rate_limit_t *rl, unsigned long val)
{
	atomic_long_set(&rl->limit, val);
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
	union {
		struct counter_t tcp_total_segments;
		struct counter_t tcp_data_segs_sent;
	};
	struct counter_t tcp_data_segs_rcvd;
	/* Rate limiting variables */
	struct rate_limit_t tcp_send_rate_pps;
	struct rate_limit_t udp_send_rate_pps;
	struct rate_limit_t tcp_rcv_rate_pps;
	struct rate_limit_t udp_rcv_rate_pps;
};

static inline bool rate_limit_check(struct cgroup_cls_state *cs, bool is_tcp,
				    bool is_send)
{
	struct rate_limit_t *rl;
	struct counter_t *counter;
	if (is_tcp) {
		/* exclude pure ACKs ==> include only data segments */
		if (is_send) {
			counter = &cs->tcp_data_segs_sent;
			rl = &cs->tcp_send_rate_pps;
		} else {
			counter = &cs->tcp_data_segs_rcvd;
			rl = &cs->tcp_rcv_rate_pps;
		}
	} else {
		if (is_send) {
			counter = &cs->udp_packets_sent;
			rl = &cs->udp_send_rate_pps;
		} else {
			counter = &cs->udp_packets_rcvd;
			rl = &cs->udp_rcv_rate_pps;
		}
	}
	for (; rl && counter; rl = rl->parent, counter = counter->parent) {
		/* Check the rate limit here. If not valid return false */
	}
	return true;
}

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
	skcd->cs = task_cls_state(current);
	sock_cgroup_set_classid(skcd, classid);
}

static inline void update_tcp_packets_sent(unsigned long val,
					   const struct sock *sk)
{
	struct cgroup_cls_state *cs;

	if (sk == NULL) {
		printk(KERN_WARNING "sock was null in tcp_send");
		atomic_long_add(1, &unknown);
		return;
	}
	cs = sk->sk_cgrp_data.cs;
	if (cs == NULL) {
		printk(KERN_WARNING "cgroup_cls_state was null in tcp_sent");
		atomic_long_add(1, &unknown);
		return;
	}
	counter_charge(&cs->tcp_packets_sent, val);
}

static inline void update_tcp_packets_rcvd(unsigned long val,
					   const struct sock *sk)
{
	struct cgroup_cls_state *cs;

	if (sk == NULL) {
		printk(KERN_WARNING "sock was null in tcp_rcvd");
		atomic_long_add(1, &unknown);
		return;
	}
	cs = sk->sk_cgrp_data.cs;
	if (cs == NULL) {
		printk(KERN_WARNING "cgroup_cls_state was null in tcp_rcvd");
		atomic_long_add(1, &unknown);
		return;
	}
	counter_charge(&cs->tcp_packets_rcvd, val);
}

static inline void update_udp_packets_sent(unsigned long val,
					   const struct sock *sk)
{
	struct cgroup_cls_state *cs;

	if (sk == NULL) {
		printk(KERN_WARNING "sock was null in udp_send");
		atomic_long_add(1, &unknown);
		return;
	}
	cs = sk->sk_cgrp_data.cs;
	if (cs == NULL) {
		printk(KERN_WARNING "cgroup_cls_state was null in udp_sent");
		atomic_long_add(1, &unknown);
		return;
	}
	counter_charge(&cs->udp_packets_sent, val);
}

static inline void update_udp_packets_rcvd(unsigned long val,
					   const struct sock *sk)
{
	struct cgroup_cls_state *cs;

	if (sk == NULL) {
		printk(KERN_WARNING "sock was null in udp_rcvd");
		atomic_long_add(1, &unknown);
		return;
	}
	cs = sk->sk_cgrp_data.cs;
	if (cs == NULL) {
		printk(KERN_WARNING "cgroup_cls_state was null in udp_rcvd");
		return;
	}
	counter_charge(&cs->udp_packets_rcvd, val);
}

static inline void update_tcp_total_segment_size(unsigned long val,
						 const struct sock *sk)
{
	struct cgroup_cls_state *cs;

	if (sk == NULL) {
		printk(KERN_WARNING "sock was null in tcp_segment_size");
		atomic_long_add(1, &unknown);
		return;
	}
	cs = sk->sk_cgrp_data.cs;
	if (cs == NULL) {
		printk(KERN_WARNING
		       "cgroup_cls_state was null in tcp_segment_size");
		return;
	}
	counter_charge(&cs->tcp_total_segment_size, val);
}

static inline void update_tcp_total_segments(unsigned long val,
					     const struct sock *sk)
{
	struct cgroup_cls_state *cs;

	if (sk == NULL) {
		printk(KERN_WARNING "sock was null in tcp_data_segs_sent");
		atomic_long_add(1, &unknown);
		return;
	}
	cs = sk->sk_cgrp_data.cs;
	if (cs == NULL) {
		printk(KERN_WARNING
		       "cgroup_cls_state was null in tcp_data_segs_sent");
		return;
	}
	counter_charge(&cs->tcp_total_segments, val);
}

static inline void update_tcp_data_segs_rcvd(unsigned long val,
					     const struct sock *sk)
{
	struct cgroup_cls_state *cs;

	if (sk == NULL) {
		printk(KERN_WARNING "sock was null in tcp_data_segs_rcvd");
		atomic_long_add(1, &unknown);
		return;
	}
	cs = sk->sk_cgrp_data.cs;
	if (cs == NULL) {
		printk(KERN_WARNING
		       "cgroup_cls_state was null in tcp_data_segs_rcvd");
		return;
	}
	counter_charge(&cs->tcp_data_segs_rcvd, val);
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
