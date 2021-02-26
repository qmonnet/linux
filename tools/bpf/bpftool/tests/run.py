#!/usr/bin/env python3

import json
import os
import subprocess
import sys

PINNED_PATH = "/sys/fs/bpf/bpftool_test"
INNER_MAP_PINNED_PATH = "/sys/fs/bpf/bpftool_test_innermap"
DEFAULT_PROG = "ret1.o"

class Tester:
    def __init__(self):
        # Number of tests that failed
        self.failures = 0
        # Number of tests known to fail
        self.expectedFailures = 0
        # Non-null if we saw an unexpected failure
        # We could use (failures > expectedFailures), but we could have a case
        # where we have both unexpected failures and unexpected successes,
        # leading to both counters to be equal
        self.retval = 0
        self.results = []

    def bpftool(args):
        try:
            complProc = subprocess.run([ "bpftool" ] + args,
                    capture_output=True, check=True)
            return None
        except subprocess.CalledProcessError as e:
            return e

    def handleResult(self, name, err, shouldPass):
        result = { "name": name, "shouldPass": shouldPass }
        if err:
            self.failures += 1
            if shouldPass:
                self.retval = 1
            else:
                self.expectedFailures += 1
            result["passed"] = False
        else:
            # Remove pinned object
            os.remove(PINNED_PATH)
            result["passed"] = True
        self.results.append(result)

class ProgTester(Tester):
    PROG_TYPES = [
        { "name": "socket",                 "shouldPass": True },
        { "name": "kprobe",                 "shouldPass": True },
        { "name": "kretprobe",              "shouldPass": True },
        { "name": "uprobe",                 "shouldPass": True },
        { "name": "uretprobe",              "shouldPass": True },
        { "name": "classifier",             "shouldPass": True },
        { "name": "action",                 "shouldPass": True },
        { "name": "tracepoint",             "shouldPass": True },
        { "name": "raw_tracepoint",         "shouldPass": True },
        { "name": "tp",                     "shouldPass": True },
        { "name": "raw_tp",                 "shouldPass": True },
        { "name": "xdp",                    "shouldPass": True },
        { "name": "perf_event",             "shouldPass": True },
        { "name": "cgroup/skb",             "shouldPass": True },
        { "name": "cgroup/sock",            "shouldPass": True },
        { "name": "cgroup/dev",             "shouldPass": True },
        { "name": "lwt_in",                 "shouldPass": True },
        { "name": "lwt_out",                "shouldPass": True },
        { "name": "lwt_xmit",               "shouldPass": True },
        { "name": "lwt_seg6local",          "shouldPass": True },
        { "name": "sockops",                "shouldPass": True },
        { "name": "sk_skb",                 "shouldPass": True },
        { "name": "sk_msg",                 "shouldPass": True },
        { "name": "lirc_mode2",             "shouldPass": True },
        { "name": "sk_reuseport",           "shouldPass": True },
        { "name": "flow_dissector",         "shouldPass": True },
        { "name": "cgroup/sysctl",          "shouldPass": True },
        { "name": "cgroup/bind4",           "shouldPass": True },
        { "name": "cgroup/bind6",           "shouldPass": True },
        { "name": "cgroup/post_bind4",      "shouldPass": True },
        { "name": "cgroup/post_bind6",      "shouldPass": True },
        { "name": "cgroup/connect4",        "shouldPass": True },
        { "name": "cgroup/connect6",        "shouldPass": True },
        { "name": "cgroup/getpeername4",    "shouldPass": True },
        { "name": "cgroup/getpeername6",    "shouldPass": True },
        { "name": "cgroup/getsockname4",    "shouldPass": True },
        { "name": "cgroup/getsockname6",    "shouldPass": True },
        { "name": "cgroup/sendmsg4",        "shouldPass": True },
        { "name": "cgroup/sendmsg6",        "shouldPass": True },
        { "name": "cgroup/recvmsg4",        "shouldPass": True },
        { "name": "cgroup/recvmsg6",        "shouldPass": True },
        { "name": "cgroup/getsockopt",      "shouldPass": True },
        { "name": "cgroup/setsockopt",      "shouldPass": True },
        { "name": "cgroup_skb/ingress",     "shouldPass": True },
        { "name": "cgroup_skb/egress",      "shouldPass": True },
        { "name": "cgroup/sock_create",     "shouldPass": True },
        { "name": "cgroup/sock_release",    "shouldPass": True },
        { "name": "sk_skb/stream_parser",   "shouldPass": True },
        { "name": "sk_skb/stream_verdict",  "shouldPass": True },
        { "name": "sk_lookup",              "shouldPass": True },
        { "name": "xdp_devmap",             "shouldPass": True },
        { "name": "xdp_cpumap",             "shouldPass": True },

        # bpftool struc_ops
        { "name": "struct_ops",             "shouldPass": False },
        # BTF required
        { "name": "tp_btf",                 "shouldPass": False },
        { "name": "fentry",                 "shouldPass": False },
        { "name": "fentry.s",               "shouldPass": False },
        { "name": "fexit",                  "shouldPass": False },
        { "name": "fexit.s",                "shouldPass": False },
        { "name": "freplace",               "shouldPass": False },
        { "name": "fmod_ret",               "shouldPass": False },
        { "name": "fmod_ret.s",             "shouldPass": False },
        { "name": "lsm",                    "shouldPass": False },
        { "name": "lsm.s",                  "shouldPass": False },
        { "name": "iter",                   "shouldPass": False },
    ]

    def progLoad(self, testName, shouldPass, objFile, progType):
        args = [ "prog", "load", objFile, PINNED_PATH ]
        if progType:
            args += [ "type", progType ]

        err = Tester.bpftool(args)
        self.handleResult(testName, err, shouldPass)

class ProgBySectionTester(ProgTester):
    def shouldFail(progType):
        return not progType["shouldPass"]

    FAILING_PROG_TYPES = [ d["name"].replace("/", ".")
            for d in filter(shouldFail, ProgTester.PROG_TYPES) ]

    def run(self):
        files = sorted(os.listdir(os.getcwd()))
        for f in files:
            if len(f) < 2 or f[-2:] != ".o" or f == DEFAULT_PROG:
                continue
            self.progLoad(testName=f,
                    shouldPass=not (f[:-2] in ProgBySectionTester.FAILING_PROG_TYPES),
                    objFile=f, progType=None)

class ProgByTypeTester(ProgTester):
    def run(self):
        for t in ProgTester.PROG_TYPES:
            self.progLoad(testName=t["name"], shouldPass=t["shouldPass"],
                    objFile=DEFAULT_PROG, progType=t["name"])

class MapTester(Tester):
    defaultMapParams = { "key": "4", "value": "4", "entries": "1" }
    MAP_TYPES = [
        { "name": "hash",                "param": defaultMapParams, "shouldPass": True },
        { "name": "array",               "param": defaultMapParams, "shouldPass": True },
        { "name": "prog_array",          "param": defaultMapParams, "shouldPass": True },
        { "name": "perf_event_array",    "param": defaultMapParams, "shouldPass": True },
        { "name": "percpu_hash",         "param": defaultMapParams, "shouldPass": True },
        { "name": "percpu_array",        "param": defaultMapParams, "shouldPass": True },
        { "name": "cgroup_array",        "param": defaultMapParams, "shouldPass": True },
        { "name": "lru_hash",            "param": defaultMapParams, "shouldPass": True },
        { "name": "lru_percpu_hash",     "param": defaultMapParams, "shouldPass": True },
        { "name": "devmap",              "param": defaultMapParams, "shouldPass": True },
        { "name": "devmap_hash",         "param": defaultMapParams, "shouldPass": True },
        { "name": "sockmap",             "param": defaultMapParams, "shouldPass": True },
        { "name": "cpumap",              "param": defaultMapParams, "shouldPass": True },
        { "name": "xskmap",              "param": defaultMapParams, "shouldPass": True },
        { "name": "sockhash",            "param": defaultMapParams, "shouldPass": True },
        { "name": "reuseport_sockarray", "param": defaultMapParams, "shouldPass": True },
        # lpm_trie keys must be at least of sizeof(struct bpf_lpm_trie_key)+1 (5),
        #  and the map requires the BPF_F_NO_PREALLOC flag (1).
        { "name": "lpm_trie",
            "param": { "key": "8", "value": "4", "entries": "1", "flag": "1" },
            "shouldPass": True },
        # Stack trace keys must be 8 or a hight multiple of 8.
        { "name": "stack_trace",
            "param": { "key": "4", "value": "8", "entries": "1" },
            "shouldPass": True },
        # Ring buffer keys and values sizes must be at zero, while the number of
        # entries must be aligned on the memory page size.
        { "name": "ringbuf",
            "param": { "key": "0", "value": "0", "entries": "4096" },
            "shouldPass": True },
        # Cgroup storage (and per-CPU equivalent) keys must be of size 8 or
        # sizeof(struct bpf_cgroup_storage_key), and must have their number of
        # entries at zero (the value is unused).
        { "name": "cgroup_storage",
            "param": { "key": "8", "value": "8", "entries": "0" },
            "shouldPass": True },
        { "name": "percpu_cgroup_storage",
            "param": { "key": "8", "value": "8", "entries": "0" },
            "shouldPass": True },
        # Queue and stack maps have no keys.
        { "name": "queue",
            "param": {             "value": "4", "entries": "1" },
            "shouldPass": True },
        { "name": "stack",
            "param": {             "value": "4", "entries": "1" },
            "shouldPass": True },
        # Map of maps need to be provided a referece to an inner map.
        { "name": "array_of_maps",
                "param": { "key": "4", "value": "4", "entries": "1",
                    "inner_map": [ "pinned", INNER_MAP_PINNED_PATH ] },
                "shouldPass": True },
        { "name": "hash_of_maps",
                "param": { "key": "4", "value": "4", "entries": "1",
                    "inner_map": [ "pinned", INNER_MAP_PINNED_PATH ] },
                "shouldPass": True },
        { "name": "sk_storage",          "param": defaultMapParams, "shouldPass": True },
        { "name": "inode_storage",       "param": defaultMapParams, "shouldPass": True },
        { "name": "task_storage",        "param": defaultMapParams, "shouldPass": True },
        # Needs BTF
        { "name": "struct_ops",          "param": defaultMapParams, "shouldPass": False },
    ]

    def __init__(self):
        super().__init__()
        # Create an inner map to use for the map-of-map types
        err = self.mapLoad(mapTypeName="array", shouldPass=True,
                param={ "key": "4", "value": "4", "entries": "1" },
                mapName="test_inner_map",
                pinnedPath=INNER_MAP_PINNED_PATH)
        if err:
            raise err

    def __del__(self):
        os.remove(INNER_MAP_PINNED_PATH)

    def mapLoad(self, mapTypeName, shouldPass, param,
            pinnedPath=PINNED_PATH, mapName="test_map"):
        args = [ "map", "create", pinnedPath, "type", mapTypeName ]
        if "key" in param:
            args += [ "key", param["key"] ]
        args += [ "value", param["value"], "entries", param["entries"],
                "name", mapName ]
        if "flag" in param:
            args += [ "flag", param["flag"] ]
        if "inner_map" in param:
            args += [ "inner_map" ] + param["inner_map"]

        return Tester.bpftool(args)

    def mapLoadType(self, mapType):
        err = self.mapLoad(mapTypeName=mapType["name"],
                shouldPass=mapType["shouldPass"], param=mapType["param"])
        self.handleResult(mapType["name"], err, mapType["shouldPass"])

    def run(self):
        for t in MapTester.MAP_TYPES:
            self.mapLoadType(t)

class GlobalTester:
    def __init__(self, jsonOutput):
        # Remove pinned objects from previous invocations, if any
        for f in [ INNER_MAP_PINNED_PATH, PINNED_PATH ]:
            try:
                os.remove(f)
            except FileNotFoundError:
                pass

        self.failures = 0
        self.expectedFailures = 0
        self.retval = 0
        self.results = {}
        self.jsonOutput = jsonOutput

        if self.jsonOutput:
            return
        if sys.stdout.isatty():
            self.PASS="\033[32mpass\033[0m"
            self.FAIL="\033[1;31mFAIL\033[0m"
            self.KTF="\033[33mknown to fail\033[0m"
            self.UNX="\033[34munexpected success\033[0m"
        else:
            self.PASS="pass"
            self.FAIL="FAIL"
            self.KTF="known to fail"
            self.UNX="unexpected success"

    def printPlainResult(self, result):
        print("{0:>30s}: ".format(result["name"]), end="")
        if result["passed"]:
            if result["shouldPass"]:
                print(self.PASS)
            else:
                print(self.UNX)
        elif not result["shouldPass"]:
            print (self.KTF)
        else:
            print (self.FAIL)

    def printPlainResults(self):
        print("# Loading programs with section names")
        for r in self.results["prog_by_section"]:
            self.printPlainResult(r)

        print("\n# Loading programs with explicit types")
        for r in self.results["prog_by_type"]:
            self.printPlainResult(r)

        print("\n# Loading maps")
        for r in self.results["maps"]:
            self.printPlainResult(r)

        print()
        if self.failures > 0:
            print(f"# {self.failures} check(s) failed (including {self.expectedFailures} expected to fail)")
        else:
            print("# all checks passed")
        pass

    def collectResults(self, completedRun, category):
        self.failures += completedRun.failures
        self.expectedFailures += completedRun.expectedFailures
        self.retval += completedRun.retval
        self.results[category] = completedRun.results

    def run(self):
        progBySec = ProgBySectionTester()
        progBySec.run()
        self.collectResults(progBySec, "prog_by_section")

        progByType = ProgByTypeTester()
        progByType.run()
        self.collectResults(progByType, "prog_by_type")

        mapTester = MapTester()
        mapTester.run()
        self.collectResults(mapTester, "maps")
        # Remove pinned inner map
        del mapTester

        if jsonOutput:
            print(json.dumps(self.results))
        else:
            self.printPlainResults()

        if self.retval == 0:
            return 0
        else:
            return 1

if __name__ == "__main__":
    jsonOutput = False
    for arg in sys.argv[1:]:
        if arg == "-j" or arg == "--json":
            jsonOutput = True
        else:
            print(f"usage: {sys.argv[0]} [-h] [-j]")
            print("optional arguments:")
            print(" -h, --help  show this help message and exit")
            print(" -j, --json  print JSON output")
            sys.exit()

    tester = GlobalTester(jsonOutput)
    sys.exit(tester.run())
