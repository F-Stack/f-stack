F-Stack 2.0 Preview 9: nginx graceful reload — from "every reload drops traffic" to a two-generation dispatching architecture

1. What this feature does and its key characteristics

Start with how bad this was. Issue #528 (duplicated by #1036) has the official answer: F-Stack's nginx does not support graceful reload; `-s reload` interrupts the service no matter how you invoke it. The reason is not complicated — in F-Stack the nginx master itself is the DPDK primary holding the NIC exclusively. A reload tears down and recreates all workers, and during that gap nobody reads the NIC queues, so traffic is lost. The only precedent in the community was the #547 dedicated receive-core patch from the DPDK 18.11 era, which no longer fits today's multi-process architecture.

This project closes the whole gap. With `graceful_reload=1`:

- **Lossless reload on HUP**: the old and the new generation of workers coexist; the new generation takes over NIC rx and dispatches packet by packet, while the old generation keeps serving existing connections until it drains. Long TCP transfers cross a reload with unchanged md5 and zero stalls; new UDP flows go to the new generation immediately, old UDP flows stay with the old one until they go idle
- **USR2 binary upgrade + WINCH**: shipping a new binary goes through the same handover protocol; the old master's workers linger while active UDP flows are still draining instead of dropping them the moment the handover completes
- **Symmetric reverse-proxy support**: the two generations pick upstream ephemeral ports of opposite parity, so replies to TCP/UDP upstream connections opened by the new generation are never mis-delivered to the old one (RX-39 and RX-40, respectively)
- **KNI/kernel coexistence unaffected**: kernel-bound traffic goes through the KNI ring and is fed to the kernel by the owning generation's worker; veth, SSH and the control plane keep working across reloads
- **Observable**: the master logs every FSM transition plus completion statistics, the workers log draining and UDP linger; 25 integration cases plus a layer of unit tests back it all up

Three keywords carry the whole thing: a **resident slim primary** (the NIC no longer restarts with nginx), **per-generation dispatching** (the software flow map plus the UDP peer table decide who owns each packet), and **bounded convergence** (draining has a hard cap; it never waits forever).

2. Main applicable scenarios

2.1 Frequent releases for long-connection services

Push, IM, gateway keepalive — these fear reloads most: on stock F-Stack one reload breaks every connection. With both generations coexisting, existing connections survive and new configuration applies to new connections at once. Measured: 36 concurrent streams across a HUP, all md5-identical, zero stalls.

2.2 Reverse proxy

The proxy case has a hidden pit: the new generation connects upstream, the SYN-ACK comes back, finds no entry in the flow map, gets treated as an established old flow and is relayed to the old generation — every new upstream connection inside the window returns 504 (RX-39). UDP proxying was worse: before the fix the worker took SIGSEGV on the first proxied datagram (RX-41). Now TCP and UDP ephemeral ports are both split by generation parity, the two generations can never share an upstream four-tuple, and each side gets its own replies.

2.3 DNS/UDP services, groundwork for QUIC

UDP has no SYN, so the TCP discriminator cannot be copied; a separate "peer table" mechanism was built for it. Request/response services like DNS never notice a reload; continuously transmitting UDP flows keep their owner inside the window until they go idle or hit the cap. HTTP/3 is not enabled in this build (`--with-http_v3_module` is off), but the applicability and the limits of four-tuple dispatching for QUIC are documented, and connection-ID routing is the follow-up direction.

2.4 Binary upgrades without downtime

Shipping code: USR2 + WINCH goes through the same handover protocol with no interruption. One thing to remember: while the old master is still alive, the new master refuses a HUP and says so in the log — without that guard, two generations become three and invariants such as port parity fall apart.

2.5 Scenarios that are not a good fit

- Expecting a QUIC connection to survive migration or client NAT rebinding: once the four-tuple changes the flow belongs to the new generation and the old connection breaks; CID routing is not implemented
- Depending on IP-fragmented large UDP replies: fragments always stay with the new generation (same as TCP today)
- Wanting reload completion pinned to sub-second precision: while old flows have not drained, completion is decided by when the old connections end, capped by `worker_shutdown_timeout` (90 s by default if unset)

3. Architectural characteristics

3.1 Process model and shared structures

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 880 420" font-family="sans-serif" font-size="13">
  <defs>
    <marker id="e9a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#456"/>
    </marker>
  </defs>
  <rect x="10" y="120" width="120" height="120" rx="8" fill="#eef" stroke="#88a"/>
  <text x="70" y="152" text-anchor="middle" font-weight="bold">Physical NIC</text>
  <text x="70" y="174" text-anchor="middle">RSS queues</text>
  <text x="70" y="192" text-anchor="middle">(DPDK)</text>
  <rect x="200" y="16" width="230" height="58" rx="8" fill="#efe" stroke="#8a8"/>
  <text x="315" y="40" text-anchor="middle" font-weight="bold">nginx master</text>
  <text x="315" y="60" text-anchor="middle">runs both generations in the window</text>
  <rect x="560" y="16" width="250" height="58" rx="8" fill="#efe" stroke="#8a8"/>
  <text x="685" y="40" text-anchor="middle" font-weight="bold">resident slim primary</text>
  <text x="685" y="60" text-anchor="middle">holds the NIC, no stack, survives reloads</text>
  <rect x="200" y="120" width="230" height="120" rx="8" fill="#ffe" stroke="#aa8"/>
  <text x="315" y="146" text-anchor="middle" font-weight="bold">G_new workers ×N (rx owner)</text>
  <text x="315" y="170" text-anchor="middle">rx → dispatcher</text>
  <text x="315" y="190" text-anchor="middle">flow map (TCP) / peer table (UDP)</text>
  <text x="315" y="210" text-anchor="middle">new flows handled locally</text>
  <rect x="560" y="120" width="230" height="120" rx="8" fill="#fee" stroke="#a88"/>
  <text x="675" y="146" text-anchor="middle" font-weight="bold">G_old workers ×N (draining)</text>
  <text x="675" y="170" text-anchor="middle">receive relayed old-flow packets</text>
  <text x="675" y="190" text-anchor="middle">keep serving existing flows</text>
  <text x="675" y="210" text-anchor="middle">replies relayed back by G_new</text>
  <rect x="170" y="290" width="650" height="105" rx="8" fill="#f2f2f2" stroke="#999"/>
  <text x="495" y="312" text-anchor="middle" font-weight="bold">Shared memory (hugepage memzones / anonymous shared block)</text>
  <rect x="180" y="322" width="145" height="60" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="252" y="346" text-anchor="middle">generation</text>
  <text x="252" y="362" text-anchor="middle">directory</text>
  <text x="252" y="378" text-anchor="middle">epoch / rx owner /</text>
  <rect x="333" y="322" width="145" height="60" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="405" y="346" text-anchor="middle">drain rings</text>
  <text x="405" y="364" text-anchor="middle">queue × gen ×</text>
  <text x="405" y="378" text-anchor="middle">rx / tx direction</text>
  <rect x="486" y="322" width="155" height="60" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="563" y="346" text-anchor="middle">UDP peer tables</text>
  <text x="563" y="364" text-anchor="middle">ff_fpeer_*, one per</text>
  <text x="563" y="378" text-anchor="middle">(proc, slot, gen)</text>
  <rect x="649" y="322" width="161" height="60" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="729" y="346" text-anchor="middle">reload shared block</text>
  <text x="729" y="364" text-anchor="middle">T2 barrier / heartbeat</text>
  <text x="729" y="378" text-anchor="middle">READY / KNI ring</text>
  <line x1="130" y1="180" x2="200" y2="180" stroke="#456" stroke-width="1.5" marker-end="url(#e9a)"/>
  <text x="165" y="172" text-anchor="middle" font-size="12">rx</text>
  <line x1="430" y1="160" x2="560" y2="160" stroke="#456" stroke-width="1.5" marker-end="url(#e9a)"/>
  <text x="495" y="152" text-anchor="middle" font-size="12">old-flow relay</text>
  <line x1="560" y1="200" x2="430" y2="200" stroke="#456" stroke-width="1.5" marker-end="url(#e9a)"/>
  <text x="495" y="222" text-anchor="middle" font-size="12">reply relay</text>
  <line x1="315" y1="74" x2="315" y2="120" stroke="#456" stroke-width="1.5" marker-end="url(#e9a)"/>
  <text x="360" y="102" font-size="12">fork / READY / park order</text>
  <path d="M200,45 C120,90 110,290 170,340" fill="none" stroke="#456" stroke-width="1.2" stroke-dasharray="5,4" marker-end="url(#e9a)"/>
  <text x="112" y="272" font-size="12">reads the directory</text>
  <path d="M690,74 C800,120 800,280 812,322" fill="none" stroke="#456" stroke-width="1.2" stroke-dasharray="5,4" marker-end="url(#e9a)"/>
  <text x="806" y="230" font-size="12" text-anchor="end">pre-creates memzones</text>
</svg>

A few points deserve their own mention:

- The slim primary only does the DPDK EAL init, holds the PCI devices and pre-creates the shared memzones (drain rings, the generation directory); it never touches the protocol stack. The nginx master and all workers are secondaries — kill and replace them as often as you like
- The primary is not resident unconditionally: it is reused by pid/comm liveness, but it also compares the startup configuration digest. If a device-side key changed (NIC binding, queue count, `mtu_enable` and friends), reuse is unsafe and the HUP is refused with the reason spelled out
- The generation directory (`ff_reload_gendir`, a hugepage memzone) is the cross-master coordination point: the monotonically increasing epoch, four slots recording each upgrading master, the rx-ownership word and the port-parity marks all live there. A HUP is two generations alternating inside one master; a USR2 is two masters each holding a slot; both scenarios share this one structure

3.2 The six-state HUP machine

On the master side a reload is modeled as the state machine T0~T5:

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 880 400" font-family="sans-serif" font-size="13">
  <defs>
    <marker id="e9b" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#456"/>
    </marker>
  </defs>
  <rect x="80" y="12" width="180" height="34" rx="8" fill="#efe" stroke="#8a8"/>
  <text x="170" y="34" text-anchor="middle" font-weight="bold">master (nginx)</text>
  <rect x="380" y="12" width="180" height="34" rx="8" fill="#fee" stroke="#a88"/>
  <text x="470" y="34" text-anchor="middle" font-weight="bold">G_old workers ×N</text>
  <rect x="650" y="12" width="180" height="34" rx="8" fill="#ffe" stroke="#aa8"/>
  <text x="740" y="34" text-anchor="middle" font-weight="bold">G_new workers ×N</text>
  <line x1="170" y1="46" x2="170" y2="384" stroke="#999" stroke-dasharray="4,4"/>
  <line x1="470" y1="46" x2="470" y2="384" stroke="#999" stroke-dasharray="4,4"/>
  <line x1="740" y1="46" x2="740" y2="384" stroke="#999" stroke-dasharray="4,4"/>
  <text x="24" y="82" font-weight="bold">T1</text>
  <line x1="170" y1="78" x2="740" y2="78" stroke="#456" stroke-width="1.5" marker-end="url(#e9b)"/>
  <text x="455" y="70" text-anchor="middle">fork the new generation (each worker writes READY: epoch&lt;&lt;32 | pid when up)</text>
  <text x="24" y="114" font-weight="bold">T2</text>
  <line x1="170" y1="110" x2="470" y2="110" stroke="#456" stroke-width="1.5" marker-end="url(#e9b)"/>
  <text x="320" y="102" text-anchor="middle">park order (rx_stopped=1, ownership untouched for now)</text>
  <line x1="470" y1="138" x2="170" y2="138" stroke="#456" stroke-width="1.5" stroke-dasharray="6,4" marker-end="url(#e9b)"/>
  <text x="320" y="130" text-anchor="middle">park ack: the loop pass that confirms "skip rx/tx from now on"</text>
  <line x1="170" y1="170" x2="740" y2="170" stroke="#456" stroke-width="1.5" marker-end="url(#e9b)"/>
  <text x="455" y="162" text-anchor="middle">all acks in → rx ownership flips; new generation starts rx, dispatcher goes live</text>
  <text x="24" y="206" font-weight="bold">T3</text>
  <line x1="740" y1="202" x2="470" y2="202" stroke="#456" stroke-width="1.5" marker-end="url(#e9b)"/>
  <text x="605" y="194" text-anchor="middle">old-flow packets relayed over; replies relayed back</text>
  <line x1="470" y1="232" x2="170" y2="232" stroke="#456" stroke-width="1.5" stroke-dasharray="6,4" marker-end="url(#e9b)"/>
  <text x="320" y="224" text-anchor="middle">1 Hz drain report: conns / snd_pending / syncache / live UDP flows</text>
  <text x="170" y="262" text-anchor="middle" font-size="12">wait for zero, capped by worker_shutdown_timeout (default 90 s)</text>
  <text x="24" y="306" font-weight="bold">T5</text>
  <line x1="170" y1="302" x2="470" y2="302" stroke="#456" stroke-width="1.5" marker-end="url(#e9b)"/>
  <text x="320" y="294" text-anchor="middle">QUIT (resent after 10 s, SIGTERM after 90 s)</text>
  <text x="470" y="330" text-anchor="middle" font-size="12">before exiting: peer table → HANDED, remaining UDP flows handed over at once</text>
  <text x="24" y="372" font-weight="bold">T0</text>
  <text x="170" y="372" text-anchor="middle" font-size="12">window closes; log: graceful reload complete (took / relay stats / ring peaks)</text>
</svg>

T2 is the most delicate step of the whole handover. After issuing the park order the master must not flip ownership right away; it has to wait until every live worker of the old generation has confirmed inside its own main loop — "from this pass on I skip rx and tx" — and acked. Without that barrier a NIC queue could end up with two consumers, or none. The companion mechanism is the heartbeat: the rx owner bumps a counter in the shared block on every loop pass, and everyone else samples it, so a stuck receiver is noticed (`reload_heartbeat_timeout_ms`) instead of being waited on forever.

3.3 The dispatcher: who owns each packet

Once the window is open, the rx path of the new generation's workers goes through the dispatcher first (`ngx_ff_flow_map_dispatcher`); TCP and UDP follow two rule sets:

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 880 450" font-family="sans-serif" font-size="13">
  <defs>
    <marker id="e9c" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#456"/>
    </marker>
  </defs>
  <rect x="330" y="14" width="220" height="32" rx="8" fill="#eef" stroke="#88a"/>
  <text x="440" y="35" text-anchor="middle" font-weight="bold">new generation rx (window, dispatcher)</text>
  <path d="M400,46 C300,60 180,70 165,80" fill="none" stroke="#456" stroke-width="1.5" marker-end="url(#e9c)"/>
  <path d="M480,46 C580,60 700,70 715,80" fill="none" stroke="#456" stroke-width="1.5" marker-end="url(#e9c)"/>
  <rect x="30" y="80" width="290" height="310" rx="8" fill="#f8f8ff" stroke="#99a"/>
  <text x="175" y="102" text-anchor="middle" font-weight="bold">TCP (proto=6)</text>
  <rect x="50" y="114" width="250" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="175" y="132" text-anchor="middle">pure SYN (no ACK) → local</text>
  <rect x="50" y="162" width="250" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="175" y="180" text-anchor="middle">look up the flow map ff_flow_map (proto in key)</text>
  <rect x="50" y="216" width="250" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="175" y="234" text-anchor="middle">hit → local (this generation's connection)</text>
  <rect x="50" y="264" width="250" height="26" rx="6" fill="#fdd" stroke="#b88"/>
  <text x="175" y="282" text-anchor="middle">miss → old generation (drain ring)</text>
  <line x1="175" y1="188" x2="175" y2="216" stroke="#456" stroke-width="1.5" marker-end="url(#e9c)"/>
  <line x1="175" y1="188" x2="175" y2="264" stroke="#456" stroke-width="1.5" marker-end="url(#e9c)"/>
  <text x="175" y="330" text-anchor="middle" font-size="12">producers: SYN admission (syncache), active connect</text>
  <text x="175" y="348" text-anchor="middle" font-size="12">before its SYN (RX-39); revocation follows the pcb</text>
  <rect x="360" y="80" width="490" height="310" rx="8" fill="#fff8f0" stroke="#a96"/>
  <text x="605" y="102" text-anchor="middle" font-weight="bold">UDP (proto=17)</text>
  <rect x="380" y="114" width="200" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="480" y="132" text-anchor="middle">own flow-map hit → local</text>
  <rect x="380" y="162" width="200" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="480" y="180" text-anchor="middle">else consult the old generation's peer table</text>
  <rect x="600" y="108" width="240" height="26" rx="6" fill="#fdd" stroke="#b88"/>
  <text x="720" y="126" text-anchor="middle">no table / NONE / wid mismatch → old gen</text>
  <rect x="600" y="144" width="240" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="720" y="162" text-anchor="middle">HANDED / dead writer → local</text>
  <rect x="600" y="180" width="240" height="26" rx="6" fill="#fdd" stroke="#b88"/>
  <text x="720" y="198" text-anchor="middle">hit, not idle → old gen</text>
  <rect x="600" y="216" width="240" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="720" y="234" text-anchor="middle">hit, idle → local + learn</text>
  <rect x="600" y="252" width="240" height="26" rx="6" fill="#fff" stroke="#bbb"/>
  <text x="720" y="270" text-anchor="middle">no hit anywhere → local (new flow)</text>
  <line x1="580" y1="175" x2="600" y2="121" stroke="#456" stroke-width="1.2" marker-end="url(#e9c)"/>
  <line x1="580" y1="175" x2="600" y2="157" stroke="#456" stroke-width="1.2" marker-end="url(#e9c)"/>
  <line x1="580" y1="175" x2="600" y2="193" stroke="#456" stroke-width="1.2" marker-end="url(#e9c)"/>
  <line x1="580" y1="175" x2="600" y2="229" stroke="#456" stroke-width="1.2" marker-end="url(#e9c)"/>
  <line x1="580" y1="175" x2="600" y2="265" stroke="#456" stroke-width="1.2" marker-end="url(#e9c)"/>
  <text x="480" y="330" text-anchor="middle" font-size="12">the old generation records the UDP four-tuples it serves (idle aging),</text>
  <text x="480" y="348" text-anchor="middle" font-size="12">PUBLISHING from T1; outsiders cannot forge entries</text>
  <rect x="30" y="404" width="820" height="30" rx="6" fill="#f2f2f2" stroke="#999"/>
  <text x="440" y="424" text-anchor="middle" font-size="12">IPv4 fragments, IPv6 extension headers, non-TCP/UDP: always local (same as TCP today)</text>
</svg>

The TCP side had a hole before RX-39: the flow map had exactly one producer (syncache, for passive opens), nobody registered the SYN of an active connect, so the upstream's SYN-ACK missed the lookup and was relayed to the old generation — every new upstream connection inside the window got a 504. The fix registers active connects before their SYN goes out, revokes when the pcb leaves the hash (RST/close/drop all covered), and adds the port parity so a four-tuple collision is impossible by construction.

UDP cannot copy that: no SYN, no reliable "new flow" signal, and G_new's flow map only holds its own entries — the server-side question is "what does the old generation have". So it is done the other way round: the old generation publishes the UDP four-tuples it is serving, and the new generation consults that table to decide relay-or-keep. The header is a three-state machine:

```
process attach → NONE        not started: the new generation forwards as before (this is the
                             state an old-binary peer is forever in — compatible)
window opens  → PUBLISHING   the always-recorded four-tuples become visible; the header
                             carries a window identity (wid) so a stale table is never trusted
process exit  → HANDED       the new generation keeps everything local from now on
```

Entries age by `reload_udp_idle_ms` (default 10 s): a flow that keeps exchanging packets keeps renewing itself; a flow nobody on the old generation serves anymore goes idle, expires, and is taken over locally by the new generation, which also learns it into its own flow map.

3.4 How draining converges

The old generation reports once per second: the TCP connection count (UDP sockets are no longer counted — otherwise any `listen ... udp` pinned every reload to the deadline), the send-queue backlog, the half-open count, plus the number of non-idle UDP flows in the peer table. The master's T3 waits for that to reach zero, capped by `worker_shutdown_timeout` (90 s by default); when the cap hits, it forces progress and the remaining UDP flows are handed over on the spot. USR2 has no master-side T3; it uses a worker-side linger: after the handover, an old worker that receives QUIT while it still has live UDP flows keeps its listener and keeps serving until the flows go idle or the cap (that same `worker_shutdown_timeout`, otherwise 30 s) is reached.

4. What was reworked and what problems were hit

The rest is a bit dry; skip this section if you don't need the implementation details and jump straight to Section 5.

4.1 Splitting the primary out of nginx

This is the foundation everything else stands on. The stock model is "the nginx master is the DPDK primary" with workers as secondaries — once the master exits, nobody owns the NIC. The rework adds a resident slim primary that only does the DPDK EAL init, holds the PCI devices and pre-creates the shared memzones (drain rings, the generation directory), never touching the protocol stack. The nginx master and every worker become secondaries, free to be killed and replaced.

The supporting cast is non-trivial: pointer translation for secondaries referencing primary memory (the fp/gp/va layouts), reuse-by-pid/comm with a startup digest comparison (a changed device-side key forces a full restart), and stopping the primary together with `nginx -s stop` so it does not turn into an orphan (that was RX-37; not repeated here).

4.2 The handover barrier, READY and the heartbeat

The T2 park barrier was covered above; two details round it out. First, a new worker writes a READY word (epoch in the high 32 bits, pid in the low ones) once it is up, and the master only enters T2 when all of them are in — handing the NIC to a generation whose listeners are not up yet is exactly the accident this prevents. Second, the heartbeat: the rx owner increments on every loop pass; if a sampler sees it stop, it stops waiting and takes the failure path. Both are "do not assume the other side is alive" defenses — this whole feature is full of them, because with two masters and a dozen-plus processes, nobody's crash may drag the others down.

4.3 Problem 1: active-connect replies went to the old generation (RX-39)

The symptom: in the proxy scenario, new upstream connections inside the window timed out 100%, with error.log full of `upstream timed out (110: Connection timed out) while connecting to upstream`. The capture was unambiguous: upstream SYN, SYN-ACK, then silence on the proxy side — the SYN-ACK carries the ACK bit, the dispatcher read it as "an established old flow", and relayed it to the old generation, whose flow map did not have it either; the packet fell into the old generation's black hole. The fix is the active registration plus port parity from 3.3, plus one more guard: while the old master of a binary upgrade is alive, the new master refuses a HUP, keeping the parity invariant safe from a third generation. Afterwards: 20/20 requests returned 200 inside the window, with upstream ports split cleanly by parity 0→1.

4.4 The three UDP pitfalls (the core of RX-40)

The design borrows the FLOW mode of Cloudflare's udpgrm (the old instance records flows on its datagram paths, entries age, unknown flows go to the new instance) and keeps Envoy hot restart's lesson in mind — it forwards every new UDP packet of the window through the parent process, and envoy#47833 records that forwarding channel blocking deadlocked parent and child. So here only "published and live" flows are relayed, everything else stays local: the smaller the relay surface, the better. Three reviewers each sent it back once; all three pitfalls are worth recording.

**Pitfall 1: recording only while publishing left the table empty on the second HUP.** The first design recorded from T1, with a one-shot snapshot of existing sessions at T1. In the measured second HUP, T3 declared draining done after 1 second and the long flows were handed over early. The reason: the old generation of round two had been the new generation of round one, its flows had all been dispatched locally, and a UDP `return` session ends with its reply — the snapshot had nothing to catch; between T1 and the first datagram the live-flow count was zero. The fix is recording all the time: from attach, every UDP datagram sent or received is recorded (one hash plus at most 32 probes against a ~256 KB table), and T1 only flips the header to PUBLISHING. The cost is one extra hash per UDP datagram in graceful mode; the correctness is worth it.

**Pitfall 2: comparing clocks across processes, where an unsigned difference read "the future" as "aged out".** The writer (old generation) and the reader (new generation) each sample CLOCK_MONOTONIC milliseconds once per loop pass, and the writer's sample often lands about 1 ms after the reader's. The reader then computes `now - last` as 0xFFFFFFFF, which is greater than any timeout under an unsigned comparison, and a live flow is treated as idle and stolen by the new generation. The fix is the signed difference `(int32_t)(now - last) > (int32_t)idle`, plus a config cap of one hour to keep real overflow out of the picture. A unit test now covers exactly this: a writer sampling 5 ms late must still count as live.

**Pitfall 3: the park order closed the publishing gate.** In a multi-worker USR2, the old master discovers the new one and issues the park order; once a sibling worker copies rx_stopped=1 into the directory, a worker that had not started publishing yet sees "I am no longer the rx owner" and — under the original gate "still owns rx to start publishing" — never publishes at all. It still acks the park, but its table stays NONE and the new generation falls back to legacy forwarding. The root cause was that "still owns rx" counted the park order as giving rx up. The gate now looks only at whether rx_owner_gen in the block has actually flipped: parking means "preparing to hand over", the flip means "handed over", and starting to publish before the ack pass is perfectly safe.

4.5 Problem 5: the linger stacked on the existing caps, doubling the worst case

The first version lingered on QUIT waiting for UDP flows, then ran the pre-existing exit path — where the shutdown timer, the listener close (a 30 s cap) and the send-queue wait each started their own clock. Stacked, the worst case approached twice the cap, and the master's 90 s SIGTERM at T5 could arrive first. The fix is one budget: the shutdown timer starts when the linger starts (and is never started twice), and when the linger ends and the exit path begins, the listener-close and send-queue clocks are set back to the moment of the first QUIT. The USR2 linger cap also aligns with `worker_shutdown_timeout`, expiring at the same moment.

4.6 RX-41, fixed in passing

Stream-udp reverse proxying could not even run before the fix: in `ngx_udp_sendmsg_chain`, the F-Stack-modified condition read `c->listening->belong_to_host` before testing `c->listening` for NULL, and an upstream connection made through `ngx_event_connect_peer` has no listening — SIGSEGV on the first datagram. One gdb stack pinned it; all three copies (one in the sendmsg chain, two in the QUIC output) now test `c->listening` first. The bug had been in the F-Stack nginx-1.28 port since the day it landed; nobody had run a UDP proxy through it, so it never blew up.

4.7 The test matrix

25 integration cases (the harness `test_graceful_reload.sh`); the reload-relevant core: rt01/rt02 (long TCP across a HUP, md5 and stall counts), rt12 (KNI management plane), rt25 (HUP loops), rt27~rt29 (primary reuse/stop/MTU refusal), rt32 (TCP proxy), rt33 (UDP server, two workers, v4+v6), rt34 (UDP proxy), rt35 (USR2+WINCH). Unit tests cover the flow-map key's protocol isolation, the peer table's record/find/age/clock-wrap behavior, port parity, and the HUP/USR2 start and withdraw conditions. Before/after comparison data is all archived; Section 5 lists the highlights.

5. How to use it, how to configure it, and the results

5.1 Configuration

f-stack side (config.ini / f-stack.conf):

```ini
[dpdk]
graceful_reload=1     # master switch, default 0, behavior identical to the old build
primary_slim=1        # the resident slim primary (a prerequisite for graceful)
reload_udp_idle_ms=10000  # how long an idle UDP flow counts as ended: 100..3600000,
                      # default 10000; changing it needs no primary restart
                      # (it is not in the config digest)
```

On the nginx side, set a `worker_shutdown_timeout` — it is both the HUP T3 cap and the USR2 linger cap; unset it is 90 s, too long for most deployments:

```nginx
worker_shutdown_timeout 25s;
```

UDP service and UDP proxying are plain stream blocks, no new directives:

```nginx
stream {
    server {
        listen 5353 udp;          # request/response DNS-style
        return "pid=$pid";
    }
    server {
        listen 5354 udp;          # UDP proxy to an upstream
        proxy_pass <UPSTREAM_IP>:53;
        proxy_responses 1;
        proxy_timeout 5s;
    }
}
```

5.2 Daily operations and logs

```bash
nginx -s reload                    # HUP: routine config change, lossless
kill -USR2  $(cat nginx.pid)       # binary upgrade: the new binary takes over
kill -WINCH $(cat nginx.pid.oldbin)# the old master's workers start draining
nginx -s stop                      # stop (the resident primary goes with it)
```

The master's error.log tells the whole story; the key lines:

```
graceful reload fsm: T2_HANDOVER -> T3_DRAIN (transition 3, elapsed 155 ms)
graceful reload complete: generation 1 now active (took 1297 ms: handover 1 ms,
    drain 1000 ms, drain forwarded 41 / relayed 41 pkts, ring peak rx 0 / tx 0)
```

Worker-side draining and UDP lines:

```
ff drain: started (drain generation, conns=0 syncache=0)
reload: publishing UDP flows (HUP), 3 in the snapshot
reload: UDP dispatch: 258 forwarded, 2 kept, 0 taken over, 0 without a peer table
ff drain: UDP linger over after 18200 ms, 0 flow(s) still active
```

When draining stalls, read the T3 stalled line (conns/snd_pending/syncache at a glance); for UDP, check how many flows in the peer table are still live.

5.3 Results (measured)

| Item | Before the fix | After the fix |
|---|---|---|
| rt33 UDP server: ownership of new flows in the window (2 workers, v4/v6) | 6 of 8 new flows answered by the old generation | new flows 240/240 all new, old flows 592/592 all old, 0 loss |
| rt33 reload completion | pinned to the 90 s deadline every round | 15 s once the old flows idle out (cap set to 25 s); non-stop long flows handed over once at the cap, 0 loss |
| rt34 UDP proxy | worker SIGSEGV on the first proxied datagram (8 times in ~3 s) | upstream port parity 0→1, old flows 493/493, new flows 120/120, done in 26 s |
| rt35 USR2+WINCH | 24/24 new datagrams unanswered after the handover, old flows lost 63/259 | clean split, 0 loss; the old worker exits after a 18.2 s linger with 0 flows left |
| rt32 TCP proxy | every new upstream connection in the window got 504 | 20/200 inside the window, upstream port parity 0→1 |
| rt01/rt02 long TCP | — | md5 identical across the HUP, 36 streams, 0 stalls |
| Regression | — | all 25 cases green, incl. the KNI management plane (rt12) and IPv6 |

5.4 Limits and advice

- **Ephemeral ports halved in steady state**: with graceful_reload=1 the two coexisting generations split TCP/UDP ephemeral ports by parity; each generation gets about half (about 27k per destination four-tuple with the default range). Ports from an explicit bind are not constrained. Very port-hungry services should evaluate this
- **QUIC migration / NAT rebinding**: once the four-tuple changes, the flow belongs to the new generation and the old connection breaks; CID routing is future work
- **IP fragments, multicast/broadcast, ICMP errors**: handled by the new generation inside the window, including fragmented large replies to the old generation's connected upstreams (large DNS answers, say)
- **UDP peer-table capacity**: 16384 entries per process; a flow that finds no free slot in its probe window is not recorded (counted as not recorded) and is treated as a new flow inside the window. Request/response DNS is unaffected; very-high-concurrency long-lived UDP flows deserve attention
- **Mixed versions**: against an old binary (no peer table), UDP keeps the old behavior — everything is relayed to the old generation, never worse than before
- **Writer-liveness granularity is about 1 s**: after the old generation crashes, the new one may keep relaying to it for up to 1 s; a table left behind by a SIGKILLed process is reset by its successor at the same coordinate
- **Multi-worker proxying depends on RSS**: upstream replies must land on the connecting worker's queue; without RSS the proxy runs on a single worker (multi-worker server-side is unaffected)
- Advice: set a `worker_shutdown_timeout` for any UDP service so convergence is bounded; request/response DNS needs nothing special

Further reading:

- Design and problem registry (Chinese, authoritative): docs/nginx_reload_spec/zh_cn/06-solution-design.md (§10.5 active TCP registration, §10.9 RX-39, §10.10 RX-40/RX-41)
- Test matrix and all measurements: docs/nginx_reload_spec/zh_cn/08-testing.md
- User guide (graceful-mode behavior and limits): doc/F-Stack_Nginx_APP_Guide.md
- Three-layer architecture docs: docs/zh_cn/01-LAYER1-ARCHITECTURE.md, 03-LAYER3-FUNCTIONS.md
- Knowledge graph: docs/zh_cn/KNOWLEDGE_GRAPH_WIKI.md
- Related issues: #528 / #1036 (official: reload unsupported), #547 (the DPDK 18.11 receive-core patch)
