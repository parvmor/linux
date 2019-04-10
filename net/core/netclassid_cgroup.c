/*
 * net/core/netclassid_cgroup.c	Classid Cgroupfs Handling
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 */

#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/fdtable.h>
#include <linux/sched/task.h>

#include <net/cls_cgroup.h>
#include <net/sock.h>

#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/kthread.h>

atomic_long_t unknown;

struct hrtimer hrt;
s64 hrt_interval = 5 * 1e9L;

enum hrtimer_restart hrt_callback(struct hrtimer *timer)
{
	printk(KERN_INFO "htimer called here");
	hrtimer_forward(timer, hrtimer_cb_get_time(timer),
			ktime_set(0, hrt_interval));
	return HRTIMER_RESTART;
}

int hrt_thread(void *data)
{
	ktime_t kt;

	kt = ktime_set(0, hrt_interval);
	hrtimer_init(&hrt, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	hrtimer_set_expires(&hrt, kt);
	hrt.function = &hrt_callback;
	hrtimer_start(&hrt, kt, HRTIMER_MODE_ABS);
	return 0;
}

static inline struct cgroup_cls_state *
css_cls_state(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct cgroup_cls_state, css) : NULL;
}

struct cgroup_cls_state *task_cls_state(struct task_struct *p)
{
	return css_cls_state(
		task_css_check(p, net_cls_cgrp_id, rcu_read_lock_bh_held()));
}
EXPORT_SYMBOL_GPL(task_cls_state);

static struct cgroup_subsys_state *
cgrp_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cgroup_cls_state *parent = css_cls_state(parent_css);
	struct cgroup_cls_state *cs;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return ERR_PTR(-ENOMEM);

	if (parent) {
		counter_init(&cs->tcp_packets_sent, &parent->tcp_packets_sent);
		counter_init(&cs->tcp_packets_rcvd, &parent->tcp_packets_rcvd);
		counter_init(&cs->udp_packets_sent, &parent->udp_packets_sent);
		counter_init(&cs->udp_packets_rcvd, &parent->udp_packets_rcvd);
		counter_init(&cs->tcp_total_segment_size,
			     &parent->tcp_total_segment_size);
		counter_init(&cs->tcp_total_segments,
			     &parent->tcp_total_segments);
		counter_init(&cs->tcp_data_segs_rcvd,
			     &parent->tcp_data_segs_rcvd);
		rate_limit_init(&cs->tcp_send_rate_pps,
				&parent->tcp_send_rate_pps);
		rate_limit_init(&cs->udp_send_rate_pps,
				&parent->udp_send_rate_pps);
		rate_limit_init(&cs->tcp_rcv_rate_pps,
				&parent->tcp_rcv_rate_pps);
		rate_limit_init(&cs->udp_rcv_rate_pps,
				&parent->udp_rcv_rate_pps);
	} else {
		/* This is the first time cgroup is being initialized (no parent) */
		counter_init(&cs->tcp_packets_sent, NULL);
		counter_init(&cs->tcp_packets_rcvd, NULL);
		counter_init(&cs->udp_packets_sent, NULL);
		counter_init(&cs->udp_packets_rcvd, NULL);
		counter_init(&cs->tcp_total_segment_size, NULL);
		counter_init(&cs->tcp_total_segments, NULL);
		counter_init(&cs->tcp_data_segs_rcvd, NULL);
		rate_limit_init(&cs->tcp_send_rate_pps, NULL);
		rate_limit_init(&cs->udp_send_rate_pps, NULL);
		rate_limit_init(&cs->tcp_rcv_rate_pps, NULL);
		rate_limit_init(&cs->udp_rcv_rate_pps, NULL);

		atomic_long_set(&unknown, 0);
		/* start a thread that logs every few seconds */
		hrt_thread(NULL);
	}
	return &cs->css;
}

static int cgrp_css_online(struct cgroup_subsys_state *css)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct cgroup_cls_state *parent = css_cls_state(css->parent);

	if (parent)
		cs->classid = parent->classid;

	return 0;
}

static void cgrp_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_cls_state(css));
}

static int update_classid_sock(const void *v, struct file *file, unsigned n)
{
	int err;
	struct socket *sock = sock_from_file(file, &err);
	struct cgroup_cls_state *cs = (struct cgroup_cls_state *)v;

	if (sock) {
		spin_lock(&cgroup_sk_update_lock);
		sock->sk->sk_cgrp_data.cs = cs;
		sock_cgroup_set_classid(&sock->sk->sk_cgrp_data,
					(unsigned long)cs->classid);
		spin_unlock(&cgroup_sk_update_lock);
	}
	return 0;
}

static void cgrp_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct task_struct *p;

	cgroup_taskset_for_each (p, css, tset) {
		task_lock(p);
		iterate_fd(p->files, 0, update_classid_sock,
			   (void *)css_cls_state(css));
		task_unlock(p);
	}
}

static u64 read_classid(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_cls_state(css)->classid;
}

static int write_classid(struct cgroup_subsys_state *css, struct cftype *cft,
			 u64 value)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	struct css_task_iter it;
	struct task_struct *p;

	cgroup_sk_alloc_disable();

	cs->classid = (u32)value;

	css_task_iter_start(css, 0, &it);
	while ((p = css_task_iter_next(&it))) {
		task_lock(p);
		iterate_fd(p->files, 0, update_classid_sock,
			   (void *)(unsigned long)cs->classid);
		task_unlock(p);
		cond_resched();
	}
	css_task_iter_end(&it);

	return 0;
}

static u64 read_tcp_packets_sent(struct cgroup_subsys_state *css,
				 struct cftype *cft)
{
	return counter_read(&css_cls_state(css)->tcp_packets_sent);
}

static u64 read_tcp_packets_rcvd(struct cgroup_subsys_state *css,
				 struct cftype *cft)
{
	return counter_read(&css_cls_state(css)->tcp_packets_rcvd);
}

static u64 read_udp_packets_sent(struct cgroup_subsys_state *css,
				 struct cftype *cft)
{
	return counter_read(&css_cls_state(css)->udp_packets_sent);
}

static u64 read_udp_packets_rcvd(struct cgroup_subsys_state *css,
				 struct cftype *cft)
{
	return counter_read(&css_cls_state(css)->udp_packets_rcvd);
}

static u64 read_avg_tcp_segment_size(struct cgroup_subsys_state *css,
				     struct cftype *cft)
{
	struct cgroup_cls_state *cls_state = css_cls_state(css);
	unsigned long num = counter_read(&cls_state->tcp_total_segment_size);
	unsigned long den = counter_read(&cls_state->tcp_total_segments);
	if (den == 0)
		return 0;
	return num / den;
}

static u64 read_tcp_send_rate_pps(struct cgroup_subsys_state *css,
				  struct cftype *cft)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	return rate_limit_read(&cs->tcp_send_rate_pps);
}

static u64 read_udp_send_rate_pps(struct cgroup_subsys_state *css,
				  struct cftype *cft)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	return rate_limit_read(&cs->udp_send_rate_pps);
}

static u64 read_tcp_rcv_rate_pps(struct cgroup_subsys_state *css,
				 struct cftype *cft)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	return rate_limit_read(&cs->tcp_rcv_rate_pps);
}

static u64 read_udp_rcv_rate_pps(struct cgroup_subsys_state *css,
				 struct cftype *cft)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	return rate_limit_read(&cs->udp_rcv_rate_pps);
}

static int write_tcp_send_rate_pps(struct cgroup_subsys_state *css,
				   struct cftype *cft, u64 val)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	rate_limit_set(&cs->tcp_send_rate_pps, val);
	return 0;
}

static int write_udp_send_rate_pps(struct cgroup_subsys_state *css,
				   struct cftype *cft, u64 val)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	rate_limit_set(&cs->udp_send_rate_pps, val);
	return 0;
}

static int write_tcp_rcv_rate_pps(struct cgroup_subsys_state *css,
				  struct cftype *cft, u64 val)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	rate_limit_set(&cs->tcp_rcv_rate_pps, val);
	return 0;
}

static int write_udp_rcv_rate_pps(struct cgroup_subsys_state *css,
				  struct cftype *cft, u64 val)
{
	struct cgroup_cls_state *cs = css_cls_state(css);
	rate_limit_set(&cs->udp_rcv_rate_pps, val);
	return 0;
}

static u64 read_unknown(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return atomic_long_read(&unknown);
}

static int write_unknown(struct cgroup_subsys_state *css, struct cftype *cft,
			 u64 val)
{
	atomic_long_set(&unknown, 0);
	return 0;
}

static struct cftype ss_files[] = {
	{
		.name = "classid",
		.read_u64 = read_classid,
		.write_u64 = write_classid,
	},
	{
		.name = "tcp_packets_sent",
		.read_u64 = read_tcp_packets_sent,
	},
	{
		.name = "tcp_packets_rcvd",
		.read_u64 = read_tcp_packets_rcvd,
	},
	{
		.name = "udp_packets_sent",
		.read_u64 = read_udp_packets_sent,
	},
	{
		.name = "udp_packets_rcvd",
		.read_u64 = read_udp_packets_rcvd,
	},
	{
		.name = "avg_tcp_segment_size",
		.read_u64 = read_avg_tcp_segment_size,
	},
	{
		.name = "tcp_send_rate_pps",
		.read_u64 = read_tcp_send_rate_pps,
		.write_u64 = write_tcp_send_rate_pps,
	},
	{
		.name = "udp_send_rate_pps",
		.read_u64 = read_udp_send_rate_pps,
		.write_u64 = write_udp_send_rate_pps,
	},
	{
		.name = "tcp_rcv_rate_pps",
		.read_u64 = read_tcp_rcv_rate_pps,
		.write_u64 = write_tcp_rcv_rate_pps,
	},
	{
		.name = "udp_rcv_rate_pps",
		.read_u64 = read_udp_rcv_rate_pps,
		.write_u64 = write_udp_rcv_rate_pps,
	},
	{
		.name = "unknown",
		.read_u64 = read_unknown,
		.write_u64 = write_unknown,
	},
	{} /* terminate */
};

struct cgroup_subsys net_cls_cgrp_subsys = {
	.css_alloc = cgrp_css_alloc,
	.css_online = cgrp_css_online,
	.css_free = cgrp_css_free,
	.attach = cgrp_attach,
	.legacy_cftypes = ss_files,
};
