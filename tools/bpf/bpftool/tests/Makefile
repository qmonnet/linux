SHELL = /bin/bash

LLVM_VERSION = -12
CLANG = clang$(LLVM_VERSION)
LLC   = llc$(LLVM_VERSION)

SRC = ret1

STRAIGHTFORWARDS_TYPES = \
	socket.o \
	sk_reuseport.o \
	classifier.o \
	action.o \
	xdp.o \
	perf_event.o \
	lwt_in.o \
	lwt_out.o \
	lwt_xmit.o \
	lwt_seg6local.o \
	cgroup_skb.ingress.o \
	cgroup_skb.egress.o \
	cgroup.skb.o \
	cgroup.sock_create.o \
	cgroup.sock_release.o \
	cgroup.sock.o \
	cgroup.post_bind4.o \
	cgroup.post_bind6.o \
	cgroup.dev.o \
	sockops.o \
	sk_skb.stream_parser.o \
	sk_skb.stream_verdict.o \
	sk_skb.o \
	sk_msg.o \
	lirc_mode2.o \
	flow_dissector.o \
	cgroup.bind4.o \
	cgroup.bind6.o \
	cgroup.connect4.o \
	cgroup.connect6.o \
	cgroup.sendmsg4.o \
	cgroup.sendmsg6.o \
	cgroup.recvmsg4.o \
	cgroup.recvmsg6.o \
	cgroup.getpeername4.o \
	cgroup.getpeername6.o \
	cgroup.getsockname4.o \
	cgroup.getsockname6.o \
	cgroup.sysctl.o \
	cgroup.getsockopt.o \
	cgroup.setsockopt.o

all: $(SRC).o $(STRAIGHTFORWARDS_TYPES) kprobe.o

define compile_with_sec_name
	$(Q)sed 's=^/\* SECTION_NAME_PLACEHOLDER \*/$$=SEC("$(2)")=' $(1) | \
		$(CLANG) -O2 -g -emit-llvm -x c -c - -o - | \
		$(LLC) -march=bpf -mcpu=v3 -filetype=obj -o $@
endef

$(SRC).o: $(SRC).c
	$(Q)$(CLANG) -O2 -g -emit-llvm -c $^ -o - | \
		$(LLC) -march=bpf -mcpu=v3 -filetype=obj -o $@

kprobe.o: $(SRC).c
	$(call compile_with_sec_name,$<,kprobe/open_at)

# struct_ops.o
# kprobe/
# uprobe/
# kretprobe/
# uretprobe/
# tracepoint/
# tp/
# raw_tracepoint/
# raw_tp/
# tp_btf/
# fentry/
# fmod_ret/
# fexit/
# fentry.s/
# fmod_ret.s/
# fexit.s/
# freplace/
# lsm/
# lsm.s/
# iter/
# xdp_devmap/
# xdp_cpumap/
# sk_lookup/

$(STRAIGHTFORWARDS_TYPES): $(SRC).c
	$(call compile_with_sec_name,$<,$(subst .,/,$(basename $@)))

clean:
	rm -rf -- *.o

.PHONY: all clean
