# trace.awk - shared engine of fwtrace and drppkt (GNU awk).
# Reads `nft monitor trace` on stdin and prints ONE decision per packet flow:
# who decided (the rule's name), what was decided and WHY.
#
#   -v mode=flow|path   flow: one line per new flow+decision
#                       path: same, plus every named rule the packet crossed
#   -v json=0|1         json: one JSON object per line (used by the log viewer)
#   -v marker=<text>    comment of our own probe rule (never reported)
#   -v ctlookup=1|0     correlate NAT hops with conntrack (default 1)
#
# The trace covers every table on the box (fw4, banIP, netifyd, snort, adblock), not only
# fw4: an IP & Geo Blocking drop lives in table banIP, an IPS hand-off in table snort.

function jesc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
function f1(re,    m) { if (match($0, re, m)) return m[1]; return "" }
function strip(c) { sub(/^!fw4: /, "", c); return c }
function nz(s, d) { return (s == "" ? d : s) }

# Human reason for a decision. Kernel log prefixes ("reject wan in", "DPI block",
# "banIP/inbound/drop/<list>") are what you see in the console; this is the same
# information plus, when there is one, the exact rule name.
function reason(tbl, chn, text, name, decision,    m) {
	if (text ~ /netify-blocked/) return "DPI: application or protocol blocked by policy"
	if (tbl == "banIP") {
		if (match(text, /@[A-Za-z0-9_.-]+/)) return "IP & Geo Blocking: matched list " substr(text, RSTART + 1, RLENGTH - 1)
		return "IP & Geo Blocking"
	}
	if (tbl == "snort") return "IPS"
	if (tbl == "adblock") return "DNS Filtering"
	if (text ~ /ct state invalid/ || name ~ /[Ii]nvalid/) return "Invalid connection state"
	if (name ~ /^Handle (forwarded|inbound) flows/) return "Established or related connection"
	if (name ~ /^(reject|drop|accept) .* traffic/) return "Zone policy: " name
	if (name != "") return "Firewall rule: " name
	if (decision == "DROP" || decision == "REJECT") return "Default policy of chain " chn
	return "Default policy"
}

function conntrack_lookup(saddr, daddr, sport, dport,    cmd, line, n, seg, a, rs, rd, result, sv, dv) {
	cmd = "conntrack -L 2>/dev/null"
	result = ""
	while ((cmd | getline line) > 0) {
		if (index(line, saddr) == 0 || index(line, daddr) == 0) continue
		if (sport != "-" && index(line, sport) == 0) continue
		if (dport != "-" && index(line, dport) == 0) continue
		n = 0
		while (match(line, /src=[^ ]+ dst=[^ ]+/)) {
			seg = substr(line, RSTART, RLENGTH); line = substr(line, RSTART + RLENGTH)
			n++; split(seg, a, " "); sv[n] = substr(a[1], 5); dv[n] = substr(a[2], 5)
		}
		if (n < 2) continue
		rs = sv[n]; rd = dv[n]
		if (rd != saddr) { result = "masqueraded: " saddr ":" sport " seen upstream, reply routed via " rd; break }
		if (rs != daddr) { result = "destination NATed: " daddr ":" dport " -> " rs; break }
	}
	close(cmd)
	return result
}

function forget(tid,    i) {
	for (i = 1; i <= nev[tid]; i++) { delete evtbl[tid, i]; delete evchn[tid, i]; delete evname[tid, i]; delete evtext[tid, i]; delete evverd[tid, i]; delete evdec[tid, i] }
	delete nev[tid]; delete pk[tid]; delete saddr[tid]; delete daddr[tid]; delete sport[tid]; delete dport[tid]
	delete proto[tid]; delete iif[tid]; delete oif[tid]
}

function emit(tid, fi, fin,    when, rn, why, nat, i, p, line, sp, dp, s, d) {
	when = strftime("%H:%M:%S")
	rn = evname[tid, fi]; if (rn == "") rn = "(" evchn[tid, fi] ")"
	why = reason(evtbl[tid, fi], evchn[tid, fi], evtext[tid, fi], evname[tid, fi], fin)
	sp = nz(sport[tid], "-"); dp = nz(dport[tid], "-")
	s = saddr[tid] (sp != "-" ? ":" sp : ""); d = daddr[tid] (dp != "-" ? ":" dp : "")

	nat = ""
	if (ctlookup) {
		for (i = 1; i <= nev[tid]; i++)
			if (evchn[tid, i] ~ /nat/ && evtext[tid, i] ~ /masquerade|snat|dnat|redirect/) { nat = conntrack_lookup(saddr[tid], daddr[tid], sp, dp); break }
	}

	if (json) {
		p = ""
		if (mode == "path")
			for (i = 1; i <= nev[tid]; i++)
				p = p (p == "" ? "" : ",") sprintf("{\"chain\":\"%s\",\"rule\":\"%s\",\"verdict\":\"%s\"}", jesc(evchn[tid, i]), jesc(evname[tid, i]), jesc(evdec[tid, i] != "" ? evdec[tid, i] : evverd[tid, i]))
		printf "{\"time\":\"%s\",\"epoch\":%d,\"tool\":\"%s\",\"proto\":\"%s\",\"src\":\"%s\",\"sport\":\"%s\",\"dst\":\"%s\",\"dport\":\"%s\",\"iif\":\"%s\",\"oif\":\"%s\",\"decision\":\"%s\",\"table\":\"%s\",\"chain\":\"%s\",\"rule\":\"%s\",\"reason\":\"%s\",\"nat\":\"%s\",\"path\":[%s]}\n",
			when, systime(), tool, jesc(nz(proto[tid], "-")), jesc(saddr[tid]), jesc(sp), jesc(daddr[tid]), jesc(dp), jesc(iif[tid]), jesc(oif[tid]), fin,
			jesc(evtbl[tid, fi]), jesc(evchn[tid, fi]), jesc(evname[tid, fi]), jesc(why), jesc(nat), p
		fflush()
		return
	}
	if (!hdr) { printf "%-8s %-5s %-22s %-22s %-7s %-30s %s\n", "TIME", "PROTO", "SRC", "DST", "ACTION", "RULE", "REASON"; hdr = 1 }
	printf "%-8s %-5s %-22s %-22s %-7s %-30s %s\n", when, nz(proto[tid], "-"), s, d, fin, substr(rn, 1, 30), why
	if (mode == "path") {
		for (i = 1; i <= nev[tid]; i++) {
			line = evname[tid, i]; if (line == "") line = evtext[tid, i]
			printf "         %-22s %-8s %s\n", (evtbl[tid, i] == "fw4" ? "" : evtbl[tid, i] "/") evchn[tid, i], (evdec[tid, i] != "" ? evdec[tid, i] : evverd[tid, i]), substr(line, 1, 70)
		}
	}
	if (nat != "") printf "         NAT: %s\n", nat
	fflush()
}

# decide the fate of one traced packet once all its lines have been read
function flush(tid,    i, n, fin, fi, key, sig) {
	if (!(tid in pk)) return
	n = nev[tid]; fin = ""; fi = 0
	# a drop/reject ends the packet: the first one is the decision
	for (i = 1; i <= n; i++) if (evdec[tid, i] == "DROP" || evdec[tid, i] == "REJECT") { fin = evdec[tid, i]; fi = i; break }
	# otherwise the packet was allowed: report the first fw4 rule that accepted it (not mangle/helper chains)
	if (fin == "") for (i = 1; i <= n; i++) if (evdec[tid, i] == "ACCEPT" && evtbl[tid, i] == "fw4" && evchn[tid, i] !~ /^mangle/) { fin = "ACCEPT"; fi = i; break }
	# an "accept" inside banIP / netifyd / snort only means "not blocked by me": not a decision worth reporting
	if (fin != "") {
		key = proto[tid] SUBSEP saddr[tid] SUBSEP sport[tid] SUBSEP daddr[tid] SUBSEP dport[tid]
		sig = fin SUBSEP evchn[tid, fi] SUBSEP evname[tid, fi]
		if (!(key in seen) || seen[key] != sig) { seen[key] = sig; emit(tid, fi, fin) }
	}
	forget(tid)
}

BEGIN { if (ctlookup == "") ctlookup = 1; if (mode == "") mode = "flow"; if (tool == "") tool = "trace" }

{
	if (!match($0, /^trace id ([0-9a-f]+) ([a-z0-9]+) ([A-Za-z0-9_]+) ([A-Za-z0-9_.-]+) (.*)$/, hd)) next
	tid = hd[1]; tbl = hd[3]; chn = hd[4]; rest = hd[5]
	if (tid != last) { if (last != "") flush(last); last = tid }

	if (rest ~ /^packet:/) {
		if (!(tid in pk)) {
			pk[tid] = 1
			saddr[tid] = f1("ip6? saddr ([0-9a-fA-F:.]+)"); daddr[tid] = f1("ip6? daddr ([0-9a-fA-F:.]+)")
			proto[tid] = f1("ip protocol ([a-z0-9]+)"); if (proto[tid] == "") proto[tid] = f1("ip6 nexthdr ([a-z0-9]+)")
			if (match($0, /(tcp|udp) sport ([0-9]+)/, q)) sport[tid] = q[2]
			if (match($0, /(tcp|udp) dport ([0-9]+)/, q)) dport[tid] = q[2]
			iif[tid] = f1("iif \"([^\"]+)\"")
		}
		if (oif[tid] == "") oif[tid] = f1("oif \"([^\"]+)\"")
		next
	}
	if (!(tid in pk)) next
	isrule = (rest ~ /^rule /); ispol = (rest ~ /^policy /)
	if (!isrule && !ispol) next

	verd = ""
	if (match(rest, /\(verdict ([a-z]+)( [^)]+)?\)/, vm)) verd = vm[1]
	if (ispol) { verd = rest; sub(/^policy /, "", verd); sub(/ .*/, "", verd) }
	comment = ""; if (match(rest, /comment "([^"]*)"/, cm)) comment = cm[1]
	if ((marker != "" && comment == marker) || rest ~ /meta nftrace set 1/) next
	if (ispol && verd == "accept") next        # falls through to the next hook: not a decision

	txt = rest; sub(/^rule /, "", txt); sub(/ \(verdict .*$/, "", txt); sub(/ comment "[^"]*"/, "", txt)
	nm = strip(comment)
	dec = ""
	if (txt ~ /(^| )reject( |$)/) dec = "REJECT"
	else if (verd == "drop") dec = "DROP"
	else if (verd == "accept") dec = "ACCEPT"
	else if (verd == "queue") dec = "QUEUE"

	if (nm != "" || dec != "") {
		k = ++nev[tid]
		if (k > 80) next
		evtbl[tid, k] = tbl; evchn[tid, k] = chn; evname[tid, k] = nm; evtext[tid, k] = txt; evverd[tid, k] = verd; evdec[tid, k] = dec
	}
}

END { if (last != "") flush(last) }
