#!/usr/bin/env bash

set -e

shopt -s nullglob

PINNED_PATH="/sys/fs/bpf/bpftool_test"
json=""
retval=0

printf "# Loading programs with section names\n"

# TODO: check for object files

# TODO: absolute path
for f in *.o; do
    if [ "${f}" = "ret1.o" ]; then
        continue
    fi

    printf "%30s:\t" "${f}"
    if bpftool prog load "${f}" "${PINNED_PATH}" 2>/dev/null && \
        [ -f "${PINNED_PATH}" ]; then
        printf "pass\n"
        rm -f "${PINNED_PATH}"
    else
        printf "FAIL\n"
        retval=$((${retval}+1))
    fi
done

printf "\n# Loading programs with explicit types\n"

prog_types=(
    socket
    kprobe
    kretprobe
    uprobe
    uretprobe
    classifier
    action
    tracepoint
    raw_tracepoint
    tp
    raw_tp
    xdp
    perf_event
    cgroup/skb
    cgroup/sock
    cgroup/dev
    lwt_in
    lwt_out
    lwt_xmit
    lwt_seg6local
    sockops
    sk_skb
    sk_msg
    lirc_mode2
    sk_reuseport
    flow_dissector
    cgroup/sysctl
    cgroup/bind4
    cgroup/bind6
    cgroup/post_bind4
    cgroup/post_bind6
    cgroup/connect4
    cgroup/connect6
    cgroup/getpeername4
    cgroup/getpeername6
    cgroup/getsockname4
    cgroup/getsockname6
    cgroup/sendmsg4
    cgroup/sendmsg6
    cgroup/recvmsg4
    cgroup/recvmsg6
    cgroup/getsockopt
    cgroup/setsockopt
    cgroup_skb/ingress
    cgroup_skb/egress
    cgroup/sock_create
    cgroup/sock_release
    sk_skb/stream_parser
    sk_skb/stream_verdict
    sk_lookup
    xdp_devmap
    xdp_cpumap
)

for t in "${prog_types[@]}"; do
    printf "%30s:\t" "${t}"
    if bpftool prog load ret1.o "${PINNED_PATH}" type "${t}" 2>/dev/null && \
        [ -f "${PINNED_PATH}" ]; then
        printf "pass\n"
        rm -f "${PINNED_PATH}"
    else
        printf "FAIL\n"
        retval=$((${retval}+1))
    fi
done

prog_types_btf=(
    struct_ops
    tp_btf
    fentry
    fentry.s
    fexit
    fexit.s
    freplace
    fmod_ret
    fmod_ret.s
    lsm
    lsm.s
    iter
)

map_types=(
    hash
    array
    prog_array
    perf_event_array
    percpu_hash
    percpu_array
    cgroup_array
    lru_hash
    lru_percpu_hash
    devmap
    devmap_hash
    sockmap
    cpumap
    xskmap
    sockhash
    reuseport_sockarray
    sk_storage
    struct_ops
    inode_storage
    task_storage
)

printf "\n# Loading maps\n"

for t in "${map_types[@]}"; do
    printf "%30s:\t" "${t}"
    if bpftool map create "${PINNED_PATH}" type "${t}" key 4 value 4 entries 1 name test_map 2>/dev/null && \
        [ -f "${PINNED_PATH}" ]; then
        printf "pass\n"
        rm -f "${PINNED_PATH}"
    else
        printf "FAIL\n"
        retval=$((${retval}+1))
    fi
done

# lpm_trie keys must be at least of sizeof(struct bpf_lpm_trie_key) + 1 (5),
# and the map requires the BPF_F_NO_PREALLOC flag (1).
printf "%30s:\t" "lpm_trie"
if bpftool map create "${PINNED_PATH}" type lpm_trie key 8 value 4 entries 1 name test_map flag 1 2>/dev/null && \
    [ -f "${PINNED_PATH}" ]; then
    printf "pass\n"
    rm -f "${PINNED_PATH}"
else
    printf "FAIL\n"
    retval=$((${retval}+1))
fi

# Stack trace keys must be 8 or a hight multiple of 8.
printf "%30s:\t" "stack_trace"
if bpftool map create "${PINNED_PATH}" type stack_trace key 4 value 8 entries 1 name test_map 2>/dev/null && \
    [ -f "${PINNED_PATH}" ]; then
    printf "pass\n"
    rm -f "${PINNED_PATH}"
else
    printf "FAIL\n"
    retval=$((${retval}+1))
fi

# Ring buffer keys and values sizes must be at zero, while the number of
# entries must be aligned on the memory page size.
printf "%30s:\t" "ringbuf"
if bpftool map create "${PINNED_PATH}" type ringbuf key 0 value 0 entries 4096 name test_map 2>/dev/null && \
    [ -f "${PINNED_PATH}" ]; then
    printf "pass\n"
    rm -f "${PINNED_PATH}"
else
    printf "FAIL\n"
    retval=$((${retval}+1))
fi

# Cgroup storage (and per-CPU equivalent) keys must be of size 8 or
# sizeof(struct bpf_cgroup_storage_key), and must have their number of entries
# at zero (the value is unused).
cgroup_storage_map_types=(
    cgroup_storage
    percpu_cgroup_storage
)

for t in "${cgroup_storage_map_types[@]}"; do
    printf "%30s:\t" "${t}"
    if bpftool map create "${PINNED_PATH}" type "${t}" key 8 value 8 entries 0 name test_map 2>/dev/null && \
        [ -f "${PINNED_PATH}" ]; then
        printf "pass\n"
        rm -f "${PINNED_PATH}"
    else
        printf "FAIL\n"
        retval=$((${retval}+1))
    fi
done

# Queue and stack maps have no keys.
nokey_map_types=(
    queue
    stack
)

for t in "${nokey_map_types[@]}"; do
    printf "%30s:\t" "${t}"
    if bpftool map create "${PINNED_PATH}" type "${t}" value 4 entries 1 name test_map 2>/dev/null && \
        [ -f "${PINNED_PATH}" ]; then
        printf "pass\n"
        rm -f "${PINNED_PATH}"
    else
        printf "FAIL\n"
        retval=$((${retval}+1))
    fi
done

# Map of maps need to be provided a referece to an inner map.
map_of_map_types=(
    array_of_maps
    hash_of_maps
)

INNER_MAP_PINNED_PATH="/sys/fs/bpf/bpftool_test_innermap"
if bpftool map create "${INNER_MAP_PINNED_PATH}" type array key 4 value 4 entries 1 name test_inner_map 2>/dev/null && \
    [ -f "${INNER_MAP_PINNED_PATH}" ]; then
    for t in "${map_of_map_types[@]}"; do
        printf "%30s:\t" "${t}"
        if bpftool map create "${PINNED_PATH}" type "${t}" key 4 value 4 entries 1 name test_map inner_map pinned "${INNER_MAP_PINNED_PATH}" 2>/dev/null && \
            [ -f "${PINNED_PATH}" ]; then
            printf "pass\n"
            rm -f "${PINNED_PATH}"
        else
            printf "FAIL\n"
            retval=$((${retval}+1))
        fi
    done
    rm -f "${INNER_MAP_PINNED_PATH}"
fi

printf "\n"
if [ "${retval}" -ne 0 ]; then
    printf "# ${retval} check(s) failed\n"
else
    printf "# all checks passed\n"
fi
exit ${retval}
