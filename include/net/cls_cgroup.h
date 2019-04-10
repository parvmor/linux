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

#include <linux/hrtimer.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>

#ifdef CONFIG_CGROUP_NET_CLASSID
extern atomic_long_t unknown;
extern s64 hrt_interval;

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
	rwlock_t rwlock;
	u64 limit;
	struct rate_limit_t *parent;
	/* token provider */
	struct hrtimer hrt;
	/* number of tokens available */
	u64 tokens;
};

static enum hrtimer_restart hrt_token_generator(struct hrtimer *hrt)
{
	struct rate_limit_t *rl;

	/* make the number of available tokens to be limit */
	rl = container_of(hrt, struct rate_limit_t, hrt);
	write_lock(&rl->rwlock);
	rl->tokens = rl->limit;
	write_unlock(&rl->rwlock);

	hrtimer_forward_now(hrt, ktime_set(0, hrt_interval));
	return HRTIMER_RESTART;
}

static inline void rate_limit_init(struct rate_limit_t *rl,
				   struct rate_limit_t *parent)
{
	ktime_t kt;

	rwlock_init(&rl->rwlock);
	write_lock(&rl->rwlock);
	rl->limit = LONG_MAX;
	rl->tokens = LONG_MAX;
	rl->parent = parent;
	write_unlock(&rl->rwlock);

	/* start a kthread to provide tokens */
	kt = ktime_set(0, hrt_interval);
	hrtimer_init(&rl->hrt, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	hrtimer_set_expires(&rl->hrt, kt);
	rl->hrt.function = &hrt_token_generator;
	hrtimer_start(&rl->hrt, kt, HRTIMER_MODE_REL);
}

static inline unsigned long rate_limit_read(struct rate_limit_t *rl)
{
	unsigned long ret;

	read_lock(&rl->rwlock);
	ret = rl->limit;
	read_unlock(&rl->rwlock);
	return ret;
}

static inline void rate_limit_set(struct rate_limit_t *rl, unsigned long val)
{
	write_lock(&rl->rwlock);
	rl->limit = val;
	if (rl->tokens > val)
		rl->tokens = val;
	write_unlock(&rl->rwlock);
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
	/* no need for this counter now :( anyway let it be here */
	struct counter_t tcp_data_segs_rcvd;
	/* Rate limiting variables */
	struct rate_limit_t tcp_send_rate_pps;
	struct rate_limit_t udp_send_rate_pps;
	struct rate_limit_t tcp_rcv_rate_pps;
	struct rate_limit_t udp_rcv_rate_pps;
};

static inline bool hrt_token_consumer(struct rate_limit_t *rl,
				      unsigned long val)
{
	bool ret = true;

	write_lock(&rl->rwlock);
	if (rl->tokens >= val)
		rl->tokens -= val;
	else
		ret = false;
	write_unlock(&rl->rwlock);
	return ret;
}

static inline void hrt_token_restorer(struct rate_limit_t *rl,
				      unsigned long val)
{
	write_lock(&rl->rwlock);
	rl->tokens += val;
	if (rl->tokens > rl->limit)
		rl->tokens = rl->limit;
	write_unlock(&rl->rwlock);
}

static inline bool rate_limit_check(struct sock *sk, bool is_tcp, bool is_send,
				    unsigned long val)
{
	struct rate_limit_t *rl, *_rl;
	struct cgroup_cls_state *cs;

	if (sk == NULL) {
		printk(KERN_WARNING "sock was null in rate_limit_check");
		atomic_long_add(1, &unknown);
		return false;
	}
	cs = sk->sk_cgrp_data.cs;
	if (cs == NULL) {
		printk(KERN_WARNING "sock was null in rate_limit_check");
		atomic_long_add(1, &unknown);
		return false;
	}

	if (is_tcp) {
		/* exclude pure ACKs ==> include only data segments */
		if (is_send)
			rl = &cs->tcp_send_rate_pps;
		else
			rl = &cs->tcp_rcv_rate_pps;
	} else {
		if (is_send)
			rl = &cs->udp_send_rate_pps;
		else
			rl = &cs->udp_rcv_rate_pps;
	}

	_rl = rl;
	/* Check bandwidth all the way upto the root */
	for (; rl; rl = rl->parent) {
		/* Check the rate limit here. If not valid return false */
		if (!hrt_token_consumer(rl, val)) {
			/* Restore the tokens */
			for (; _rl != rl->parent; _rl = _rl->parent)
				hrt_token_restorer(_rl, val);
			return false;
		}
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

static inline bool rate_limit_check(struct sock *sk, bool is_tcp, bool is_send,
				    unsigned long val)
{
	return false;
}

static inline void update_tcp_packets_sent(unsigned long val,
					   const struct sock *sk)
{
}

static inline void update_tcp_packets_rcvd(unsigned long val,
					   const struct sock *sk)
{
}

static inline void update_udp_packets_sent(unsigned long val,
					   const struct sock *sk)
{
}

static inline void update_udp_packets_rcvd(unsigned long val,
					   const struct sock *sk)
{
}

static inline void update_tcp_total_segment_size(unsigned long val,
						 const struct sock *sk)
{
}

static inline void update_tcp_total_segments(unsigned long val,
					     const struct sock *sk)
{
}

static inline void update_tcp_data_segs_rcvd(unsigned long val,
					     const struct sock *sk)
{
}
#endif /* CONFIG_CGROUP_NET_CLASSID */
#endif /* _NET_CLS_CGROUP_H */
