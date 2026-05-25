# How eBPF works — and how Tetragon uses it in Watergon

A deep-dive on the technology that powers the green boxes in [`architecture.png`](architecture.png). Written to be read end-to-end: each section sets up the next.

---

## 1. Why eBPF exists

The Linux kernel runs in a privileged address space that user programs cannot enter. That is a security property — but it is also a productivity ceiling. Anyone who wants to add a new capability to the kernel has historically had two options:

1. **Patch the kernel.** Get the change accepted upstream, wait for it to land in a release, wait for distributions to package that release, wait for fleets to upgrade. Multi-year cycles. The dominant model for the last 30 years.
2. **Write a kernel module.** Ships out-of-tree, links against unstable internal APIs, runs with full kernel privilege, and one wrong dereference panics the host. Module crashes are not catchable. Every kernel version bump breaks the ABI.

Neither option works for runtime security, observability, or networking tools that need to:

- ship faster than kernel release cadence,
- run on hosts whose kernel they do not control,
- fail safely (a panic in a security agent must not panic the host).

eBPF closes that gap. From the [ebpf.io intro](https://ebpf.io/what-is-ebpf/):

> eBPF is a revolutionary technology with origins in the Linux kernel that can run sandboxed programs in a privileged context such as the operating system kernel.

The analogy people use is *JavaScript for the kernel*: a small, verified, JIT-compiled bytecode that runs inside the kernel at hook points, with a stable helper API so the same bytecode keeps working across kernel versions. You write a program in restricted C, compile it to BPF bytecode with `clang -target bpf`, hand it to the kernel via the `bpf(2)` syscall, and the kernel decides — at load time — whether it is safe to run.

If you remember one thing: **eBPF made it possible to add kernel features at runtime, safely, without root-owning the kernel codebase.**

---

## 2. What "eBPF" actually means

"BPF" originally stood for *Berkeley Packet Filter* — the 1992 Van Jacobson packet-filter VM used by tcpdump. The "e" was added in 2014 when Alexei Starovoitov rewrote it into a general-purpose 64-bit register-based VM. Today the name is just **eBPF**; it no longer expands. The kernel community treats it as a standalone term.

Concretely, eBPF is four things bundled together:

| Component | What it is |
|---|---|
| **A bytecode ISA** | 10 64-bit registers + a stack + a small set of instructions. Compilable from C, Rust, Go. |
| **A verifier** | A static analyzer inside the kernel that proves the bytecode is safe before it ever runs. |
| **A JIT compiler** | Lowers verified bytecode to native machine code (x86-64, arm64, …) for performance parity with C. |
| **A hook system** | Well-defined event points in the kernel and user space where eBPF programs can attach. |

And around those four, a runtime ecosystem: **maps** for state, **helpers** for the kernel API, **CO-RE/BTF** for portability, and **libbpf / cilium-ebpf / aya** for loaders.

---

## 3. Program lifecycle: from C to running in the kernel

```
                    user space                |               kernel
                                              |
  +-------------+   bpf(2)   +-----------+    |    +----------+   JIT   +-----------+
  | clang -O2   | ---------> | verifier  | ---|--> | bytecode | ------> | native    | --> attaches at hook
  | -target bpf |  syscall   |  (checks) |    |    | (eBPF)   |         | machine   |     point, fires on
  +-------------+            +-----------+    |    +----------+         | code      |     every event
                                              |                         +-----------+
```

Five stages happen every time an eBPF program loads:

1. **Compile.** Source code (restricted C — no unbounded loops, no global functions) is compiled to BPF bytecode by Clang/LLVM.
2. **Load.** A user-space loader calls `bpf(BPF_PROG_LOAD, ...)` with the bytecode, the program type (`BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`, `BPF_PROG_TYPE_XDP`, …), and metadata.
3. **Verify.** The kernel verifier walks every possible execution path and proves the program is safe (see §4). If it cannot prove safety, the load fails with `-EINVAL` and an explanatory log.
4. **JIT.** The verified bytecode is compiled to native instructions for the host CPU. From this point on it runs at near-native speed.
5. **Attach.** The loader hooks the program at the chosen event point (`BPF_LINK_CREATE` or `perf_event_open` + `PERF_EVENT_IOC_SET_BPF`). From that moment, every time the event fires, the program runs.

A loaded program lives until either (a) the file descriptor that owns it is closed and no link or pin holds it open, or (b) the kernel is rebooted.

---

## 4. The verifier — why eBPF is safe

The verifier is the single most important component. It is what makes "let userspace inject code into the kernel" not insane.

From [ebpf.io](https://ebpf.io/what-is-ebpf/):

> The verifier is meant as a safety tool, checking that programs are safe to run. It is not a security tool inspecting what the programs are doing.

It enforces, before the program is JIT-compiled and loaded:

- **Termination.** No unbounded loops. Backward jumps are allowed only when the verifier can prove a bounded exit. (Modern kernels permit bounded `for` loops via the `BPF_LOOP` helper.)
- **Memory safety.** Every pointer dereference is checked against the verifier's tracked range. Reading from a packet beyond `data_end` is rejected. Reading from an uninitialized stack slot is rejected.
- **Type safety.** The verifier tracks the type and provenance of every value in every register on every path.
- **Bounded complexity.** The number of instructions the verifier will analyze is capped (currently 1 million per program). Programs that branch too widely simply will not load.
- **Privilege checks.** Without `CAP_BPF` (or older `CAP_SYS_ADMIN`), most program types cannot be loaded at all.
- **Spectre mitigations.** Constant blinding, JIT retpolines, and bounds masking are applied during JIT.

The verifier is *conservative*. It rejects programs that are actually safe but which it cannot prove are safe. The eBPF developer experience is, in large part, the experience of arguing with the verifier.

---

## 5. State and helpers — how eBPF programs are useful

A verified BPF program by itself can compute things on local data, but it cannot persist anything, cannot call arbitrary kernel functions, and cannot talk to user space. Three primitives close that gap.

### Maps

A **map** is a kernel data structure that BPF programs and user space can both read and write. It is the only way an eBPF program persists state across invocations or shares data with user space.

| Map type | Use |
|---|---|
| `BPF_MAP_TYPE_HASH` | Generic key-value, e.g. PID → metadata |
| `BPF_MAP_TYPE_ARRAY` | Fixed-size lookup table |
| `BPF_MAP_TYPE_PERCPU_HASH` / `_ARRAY` | One copy per CPU; lock-free |
| `BPF_MAP_TYPE_LRU_HASH` | Bounded; evicts oldest |
| `BPF_MAP_TYPE_RINGBUF` | MPSC ring buffer for streaming events to user space |
| `BPF_MAP_TYPE_LPM_TRIE` | Longest-prefix match (IP routing) |
| `BPF_MAP_TYPE_STACK_TRACE` | Captured stack frames |

Watergon's Tetragon DS uses ring buffers internally to stream `process_exec` and `process_kprobe` events from kernel to the Tetragon agent in user space.

### Helpers

A BPF program cannot call kernel functions directly — the kernel ABI is unstable. Instead, the kernel exposes a fixed set of **helper functions** (currently 200+) that programs may call. Examples:

- `bpf_get_current_pid_tgid()` — current process ID
- `bpf_probe_read_user(dst, size, src)` — copy from a user-space address into BPF stack
- `bpf_perf_event_output()` / `bpf_ringbuf_output()` — push event to user space
- `bpf_send_signal(sig)` — deliver a signal to the current task (this is what Tetragon `SIGKILL` enforcement uses)
- `bpf_override_return(retval)` — set the return value of a kprobed function (the other enforcement primitive)

Helpers are versioned but stable, which is what lets a BPF program written today keep running on next year's kernel.

### Tail calls

A program may call another loaded program via `bpf_tail_call()`. This replaces the current program's execution context, similar to `execve()`. Used to compose larger logic out of small verified pieces — useful because each individual program is bounded in size and complexity.

---

## 6. Hook points — where programs attach

eBPF is event-driven. The kernel exposes attachment points for almost every interesting event:

| Hook | Fires on | Used for |
|---|---|---|
| **kprobe / kretprobe** | Entry/exit of any non-inlined kernel function | Generic tracing |
| **tracepoint** | Static instrumentation points compiled into the kernel | Stable, lower-overhead tracing |
| **raw_tracepoint** | Same points, no perf-event marshalling | High-throughput tracing |
| **fentry / fexit** | Function entry/exit, faster than kprobes (uses BPF trampoline) | Modern replacement for kprobes |
| **uprobe / uretprobe** | Entry/exit of user-space functions | Trace `bash` `readline`, etc. |
| **USDT** | User-space static probes embedded in binaries | Application-defined events |
| **LSM hooks** | Linux Security Module decision points (`file_open`, `bprm_check_security`, …) | Mandatory access control |
| **XDP** | First-touch packet on the NIC driver path | Highest-performance networking |
| **tc (clsact)** | Packets at the traffic-control layer | Networking + filtering |
| **socket filters / sock_ops** | Per-socket events | L4 policy |
| **cgroup hooks** | `connect()`, `bind()`, `sendmsg()` inside a cgroup | Container network policy |
| **perf events** | Hardware counters, software events | Profiling |

Tetragon, the only eBPF tool Watergon ships, uses **kprobes**, **tracepoints**, and (optionally) **LSM hooks**.

---

## 7. CO-RE and BTF — portability across kernels

A kprobe attached to `do_sys_openat2` only works if `do_sys_openat2` exists in the running kernel and has the same argument layout the BPF program expects. Across kernel versions, struct layouts shift, fields rename, functions get inlined. Naively, you would need to ship one BPF program per kernel.

**CO-RE** (Compile Once, Run Everywhere) solves this. CO-RE relies on **BTF** (BPF Type Format), a compact debug-info format embedded in the running kernel image at `/sys/kernel/btf/vmlinux`. At load time, the BPF loader compares the kernel's BTF against the BTF the program was compiled with, and rewrites the program's struct field offsets to match the running kernel.

So a CO-RE BPF program built today against kernel 5.10 BTF will, when loaded on a 6.8 host, have its struct accesses relocated transparently. This is what makes Tetragon a single container image instead of a kernel-version-matrix nightmare.

Watergon's kind nodes run a modern Ubuntu kernel with BTF baked in, so CO-RE just works.

---

## 8. How Tetragon uses eBPF

Tetragon is "eBPF-based Security Observability and Runtime Enforcement" (Cilium project). It is **not** a single eBPF program — it is a small set of long-lived BPF programs plus a user-space agent that drives them.

### 8.1 The built-in process tree (no policy needed)

The moment Tetragon loads, it attaches BPF programs to the kernel's `sched_process_exec` tracepoint and `do_exit` function. These programs:

- Capture every `execve()` and process exit on the node.
- Read process attributes (PID, UID, binary path, argv, cwd, parent exec_id, cgroup) from kernel structures.
- Resolve container metadata by mapping cgroup IDs to Kubernetes pod / container metadata (which the Tetragon agent maintains in BPF maps).
- Stream `process_exec` and `process_exit` events through a ring-buffer map to the user-space agent.

This is why Watergon's Wazuh dashboard shows pod, container, namespace, and workload fields on every event — Tetragon resolved them in-kernel before the event left the host.

`exec_id` is base64-encoded `nodename:starttime_in_jiffies:pid` and is the canonical identifier Tetragon uses to correlate parent/child across events. You see it in every `process.exec_id` field in the JSON.

### 8.2 TracingPolicy — declarative kprobes

A `TracingPolicy` is a CRD. Each TracingPolicy compiles down to one or more eBPF programs attached at the hook points the policy declares:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "monitor-tcp-connect"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchNamespaces:
      - namespace: "Pid"
        operator: "NotIn"
        values: ["host_ns"]
```

When this YAML is applied, the Tetragon agent:

1. Picks a BPF program template for `kprobe`.
2. Patches in the function name (`tcp_connect`), the argument types (`sock` → known BTF type, fields auto-extracted), and the selectors (compiled to in-kernel match expressions).
3. Loads the program through libbpf, verifies it, attaches it to the kprobe.

From then on, every `tcp_connect()` call in the kernel runs the BPF program. The program reads the `sock *` argument, walks the BTF-known fields (`sk_family`, `sk_daddr`, `sk_dport`), evaluates the selectors **in the kernel**, and only if they match emits a `process_kprobe` event to user space.

The Tetragon docs enumerate every hook point a TracingPolicy can target:

| Hook block | Attachment |
|---|---|
| `spec.kprobes[]` | kprobe / kretprobe |
| `spec.tracepoints[]` | tracepoint (or raw tracepoint with `raw: true`) |
| `spec.uprobes[]` | uprobe in a specified binary |
| `spec.usdts[]` | USDT probe by provider+name |
| `spec.lsmhooks[]` | LSM BPF hook |

And the argument types it can decode (each is a small BPF helper that knows how to walk that struct):

> `int`, `int64`, `uint64`, `size_t`, `string`, `char_buf`, `char_iovec`, `file`, `path`, `sock`, `sockaddr`, `linux_binprm`, `syscall64`, `cred`, `capability`, `dentry`, `bpf_prog`, …

This is how a TracingPolicy can say "give me the struct file pointer argument 0 of `security_file_open` and resolve its `.f_path` to a string" without you writing any BPF code.

### 8.3 In-kernel selectors — why noise stays low

A naive tracing tool generates millions of events per second on a busy host and drops them on user-space's lap. Tetragon avoids that with **selectors**: predicates that run inside the BPF program, in the kernel, before the event is emitted.

Selectors filter on:

- `matchPIDs` — by PID, by NamespacePID, by parent
- `matchBinaries` — by `/path/to/exe`
- `matchNamespaces` — by pod, by container, by host
- `matchCapabilities` — only when EUID/effective-caps include X
- `matchArgs` — by the value of the kprobed function's arguments (string equality, prefix, postfix, mask)
- `matchActions` — what to do on a match (see next section)

The selector is compiled into BPF instructions and evaluated on every fire. If it does not match, **the event is never emitted to user space**. No ring-buffer write, no syscall, no JSON serialization. This is the single biggest reason Tetragon's overhead is measured in fractions of a percent CPU instead of double-digits.

Watergon exploits this with the Tetragon `exportAllowList` in [`manifests/tetragon/values.yaml`](../manifests/tetragon/values.yaml) — events outside `vulnerable-apps` / `security-testing` are filtered out at the namespace level.

### 8.4 Enforcement — actually blocking things

So far everything has been observation. Tetragon also supports **enforcement** — using the BPF program to actively prevent the kernel operation. Two primitives:

| Action | Mechanism | Effect |
|---|---|---|
| `Sigkill` | `bpf_send_signal(SIGKILL)` helper | Delivers a kill signal to the current task synchronously, inside the BPF program. Process dies. |
| `Override` | `bpf_override_return(error_code)` helper | Sets the return value of the kprobed function before the original function body runs. Caller sees an error. Requires `CONFIG_BPF_KPROBE_OVERRIDE` and `CAP_SYS_ADMIN`. |

The Tetragon enforcement docs are blunt about the caveat:

> A `SIGKILL` during a `write()` call may not prevent data from being written. To guarantee operation prevention, signals should be combined with the `Override` action.

In other words: `SIGKILL` kills the process, but the syscall already in flight may complete before the task is reaped. For real prevention you intercept the function and return an error from it.

Watergon does **not** currently use enforcement. The `delete-pod.py` script in [`manifests/wazuh-agent/agent-image/`](../manifests/wazuh-agent/agent-image/) is a Wazuh *Active Response* — it runs in user space after Wazuh raises an alert, and calls the Kubernetes API to delete the pod. That is async, not inline. Tetragon-style enforcement (kill in the BPF program itself) is a future-work item noted in the README.

### 8.5 The export pipeline

Once an event leaves the BPF program through a ring-buffer map, here is what happens:

```
BPF program (in kernel)
   |
   |  bpf_ringbuf_output(event)
   v
ring-buffer map  <-- consumed by user-space Tetragon agent
   |
   |  enrich with pod/container/namespace metadata
   v
JSON event
   |
   |  written line-by-line to /var/run/cilium/tetragon/tetragon.log (hostPath)
   v
Wazuh agent DaemonSet (Watergon)
   |
   |  tails the hostPath log
   v
tcp:1514 -> wazuh-manager-worker
   |
   |  decoded by 0700-tetragon-decoder.xml
   |  matched by rules 700000..700099
   v
alerts.json -> filebeat -> wazuh-indexer -> dashboard
```

The Tetragon agent in user space is a Go program that consumes ring-buffer events, enriches them with pod/container metadata it has cached from the Kubernetes API, and writes them either to gRPC, stdout, or a file. Watergon configures it to write JSON lines to `/var/run/cilium/tetragon/tetragon.log` on each node, via the file exporter — and that hostPath is what the Wazuh agent then tails.

---

## 9. How this maps to Watergon

Pointer | What it does in eBPF terms
---|---
[`manifests/tetragon/values.yaml`](../manifests/tetragon/values.yaml) | Helm values for the Tetragon DS. Sets `exportAllowList` (in-kernel selector at the namespace level) and the export file path.
[`manifests/tetragon/tracingpolicies.yaml`](../manifests/tetragon/tracingpolicies.yaml) | TracingPolicy CRDs — declarative kprobes that compile to additional BPF programs at runtime.
[`manifests/wazuh-agent/daemonset.yaml`](../manifests/wazuh-agent/daemonset.yaml) | hostPID + hostNetwork + hostPath mount of `tetragon.log`. The agent tails events that the BPF programs produced.
[`manifests/wazuh-agent/rules-cm.yaml`](../manifests/wazuh-agent/rules-cm.yaml) | Wazuh decoder + rules. These run in **user space** on the manager, after BPF has already extracted and forwarded the event.

So when DVWA execs `/bin/sh`, the chain is:

1. The kernel runs `execve("/bin/sh", ...)` for the PHP container.
2. Tetragon's `sched_process_exec` BPF program fires, captures argv, resolves cgroup → pod = `dvwa-*` in namespace `vulnerable-apps`.
3. Allowlist selector matches `vulnerable-apps` → event is emitted via ring buffer.
4. User-space Tetragon agent enriches and writes JSON to `tetragon.log`.
5. Wazuh agent DS tails the line and forwards it on tcp 1514.
6. Wazuh worker decodes via the JSON decoder, matches rule 700004 (shell), rule 700099 (audit), writes an alert.
7. Indexer indexes; dashboard renders.

Everything from steps 1–3 happens in the kernel, in microseconds, with no copy to user space until the selector decides the event is interesting.

---

## 10. Further reading

- [ebpf.io — What is eBPF?](https://ebpf.io/what-is-ebpf/) — the canonical primer.
- [ebpf.io — Blog](https://ebpf.io/blog/) — case studies (Datadog, GitHub, Nutanix). Recent posts on CO-RE portability, ring-buffer use, file-monitoring at scale.
- [Tetragon docs — Concepts](https://tetragon.io/docs/concepts/) — TracingPolicy, selectors, enforcement, hook points.
- [Tetragon docs — TracingPolicy reference](https://tetragon.io/docs/reference/tracing-policy/) — every field of the CRD with type and example.
- Brendan Gregg's [BPF Performance Tools](http://www.brendangregg.com/bpf-performance-tools-book.html) — the book on eBPF tracing.
- Linux kernel: `Documentation/bpf/` — the verifier, helpers, and ABI from the source.
