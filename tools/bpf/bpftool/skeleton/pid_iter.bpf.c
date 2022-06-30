// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "pid_iter.h"

/* keep in sync with the definition in main.h */
enum bpf_obj_type {
	BPF_OBJ_UNKNOWN,
	BPF_OBJ_PROG,
	BPF_OBJ_MAP,
	BPF_OBJ_LINK,
	BPF_OBJ_BTF,
};

enum bpf_link_type___local {
	BPF_LINK_TYPE_PERF_EVENT = 7,
};

struct bpf_iter_meta___local {
	struct seq_file *seq;
} __attribute__((preserve_access_index));

struct bpf_iter__task_file___local {
	struct bpf_iter_meta___local *meta;
	struct task_struct *task;
	struct file *file;
} __attribute__((preserve_access_index));

struct bpf_link___local {
	u32 id;
	enum bpf_link_type___local type;
} __attribute__((preserve_access_index));

struct bpf_perf_link___local {
	struct bpf_link___local link;
	struct file *perf_file;
} __attribute__((preserve_access_index));

struct perf_event___local {
	u64 bpf_cookie;
} __attribute__((preserve_access_index));

extern const void bpf_link_fops __ksym;
extern const void bpf_map_fops __ksym;
extern const void bpf_prog_fops __ksym;
extern const void btf_fops __ksym;

const volatile enum bpf_obj_type obj_type = BPF_OBJ_UNKNOWN;

static __always_inline __u32 get_obj_id(void *ent, enum bpf_obj_type type)
{
	switch (type) {
	case BPF_OBJ_PROG:
		return BPF_CORE_READ((struct bpf_prog *)ent, aux, id);
	case BPF_OBJ_MAP:
		return BPF_CORE_READ((struct bpf_map *)ent, id);
	case BPF_OBJ_BTF:
		return BPF_CORE_READ((struct btf *)ent, id);
	case BPF_OBJ_LINK:
		return BPF_CORE_READ((struct bpf_link___local *)ent, id);
	default:
		return 0;
	}
}

/* could be used only with BPF_LINK_TYPE_PERF_EVENT links */
static __u64 get_bpf_cookie(struct bpf_link___local *link)
{
	struct bpf_perf_link___local *perf_link = NULL;
	struct perf_event___local *event;

	if (!bpf_core_field_exists(perf_link->link))
		return 0;

	perf_link = container_of(link, struct bpf_perf_link___local, link);
	event = BPF_CORE_READ(perf_link, perf_file, private_data);
	return BPF_CORE_READ(event, bpf_cookie);
}

SEC("iter/task_file")
int iter(struct bpf_iter__task_file___local *ctx)
{
	struct file *file = BPF_CORE_READ(ctx, file);
	struct task_struct *task = BPF_CORE_READ(ctx, task);
	struct seq_file *seq = BPF_CORE_READ(ctx, meta, seq);
	struct pid_iter_entry e;
	const void *fops;

	if (!file || !task)
		return 0;

	switch (obj_type) {
	case BPF_OBJ_PROG:
		fops = &bpf_prog_fops;
		break;
	case BPF_OBJ_MAP:
		fops = &bpf_map_fops;
		break;
	case BPF_OBJ_BTF:
		fops = &btf_fops;
		break;
	case BPF_OBJ_LINK:
		fops = &bpf_link_fops;
		break;
	default:
		return 0;
	}

	if (file->f_op != fops)
		return 0;

	__builtin_memset(&e, 0, sizeof(e));
	e.pid = task->tgid;
	e.id = get_obj_id(file->private_data, obj_type);

	if (obj_type == BPF_OBJ_LINK &&
	    bpf_core_enum_value_exists(enum bpf_link_type___local, BPF_LINK_TYPE_PERF_EVENT)) {
		struct bpf_link___local *link = (struct bpf_link___local *) file->private_data;

		if (BPF_CORE_READ(link, type) == bpf_core_enum_value(enum bpf_link_type___local,
								     BPF_LINK_TYPE_PERF_EVENT)) {
			e.has_bpf_cookie = true;
			e.bpf_cookie = get_bpf_cookie(link);
		}
	}

	bpf_probe_read_kernel_str(&e.comm, sizeof(e.comm),
				  task->group_leader->comm);
	bpf_seq_write(seq, &e, sizeof(e));

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
