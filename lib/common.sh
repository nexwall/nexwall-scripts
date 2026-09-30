# common.sh - filter parsing, probe rules and process handling shared by fwtrace and drppkt.
# Sourced by the tools; not meant to be run directly.
#
# The probe is a non-terminating `meta nftrace set 1` rule: it only flags matching packets so the
# kernel reports the rules they cross. It never accepts, drops or rewrites anything.

NX_TABLE_FAM=inet
NX_TABLE=fw4
NX_LIBDIR=${NX_LIBDIR:-/usr/lib/nexwall-scripts}
[ -r "$NX_LIBDIR/trace.awk" ] || NX_LIBDIR=$(dirname "$0")/../lib
NX_AWK="$NX_LIBDIR/trace.awk"

nx_die() { echo "$NX_NAME: $*" >&2; exit 2; }

# --- validation: the filter ends up inside an nft rule, so nothing but plain addresses,
# --- ports and protocol names is ever accepted.
nx_valid_addr() { case "$1" in ''|*[!0-9a-fA-F:./]*) return 1 ;; esac; return 0; }
nx_valid_port() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
nx_valid_proto() { case "$1" in tcp|udp|icmp|icmpv6) return 0 ;; esac; return 1; }
nx_af() { case "$1" in *:*) echo ip6 ;; *) echo ip ;; esac; }

# nx_parse_filter <tokens...>  ->  sets NX_HOST NX_NET NX_PORT NX_PROTO (+ direction of each)
nx_parse_filter() {
	_dir=dst; NX_HOST=""; NX_NET=""; NX_PORT=""; NX_PROTO=""
	NX_HOSTDIR=dst; NX_NETDIR=dst; NX_PORTDIR=dst
	while [ $# -gt 0 ]; do
		case "$1" in
			and) shift ;;
			src) _dir=src; shift ;;
			dst) _dir=dst; shift ;;
			host) [ $# -ge 2 ] && nx_valid_addr "$2" || nx_die "invalid host"; NX_HOST=$2; NX_HOSTDIR=$_dir; _dir=dst; shift 2 ;;
			net) [ $# -ge 2 ] && nx_valid_addr "$2" || nx_die "invalid net"; NX_NET=$2; NX_NETDIR=$_dir; _dir=dst; shift 2 ;;
			port) [ $# -ge 2 ] && nx_valid_port "$2" || nx_die "invalid port"; NX_PORT=$2; NX_PORTDIR=$_dir; _dir=dst; shift 2 ;;
			proto) [ $# -ge 2 ] && nx_valid_proto "$2" || nx_die "invalid proto (tcp|udp|icmp|icmpv6)"; NX_PROTO=$2; shift 2 ;;
			*) nx_die "unrecognized filter token: $1" ;;
		esac
	done
	[ -n "$NX_HOST$NX_NET$NX_PORT$NX_PROTO" ] || nx_die "no filter given (refusing to trace all traffic)"
}

# direction word -> nft letter (src -> s, dst -> d), flipped when swapping
nx_letter() { _l=$1; if [ "$2" = 1 ]; then [ "$_l" = src ] && _l=dst || _l=src; fi; [ "$_l" = src ] && echo s || echo d; }

# nx_match <swap>  -> prints the nft match expression; swap=1 reverses every direction
nx_match() {
	_m=""
	[ -n "$NX_PROTO" ] && _m="$_m meta l4proto $NX_PROTO"
	[ -n "$NX_HOST" ] && _m="$_m $(nx_af "$NX_HOST") $(nx_letter "$NX_HOSTDIR" "$1")addr $NX_HOST"
	[ -n "$NX_NET" ] && _m="$_m $(nx_af "$NX_NET") $(nx_letter "$NX_NETDIR" "$1")addr $NX_NET"
	[ -n "$NX_PORT" ] && _m="$_m th $(nx_letter "$NX_PORTDIR" "$1")port $NX_PORT"
	echo "$_m"
}

# nx_insert_probes <chains...>  (uses NX_TAG, NX_BOTH); sets NX_INSERTED
nx_insert_probes() {
	NX_INSERTED=""
	_fwd=$(nx_match 0); _rev=$(nx_match 1)
	for _c in "$@"; do
		if nft insert rule $NX_TABLE_FAM $NX_TABLE $_c $_fwd meta nftrace set 1 comment "\"$NX_TAG\"" 2>/dev/null; then
			NX_INSERTED="$NX_INSERTED $_c"
			# the return direction is where a DPI/banIP verdict usually shows up
			[ "$NX_BOTH" = 1 ] && nft insert rule $NX_TABLE_FAM $NX_TABLE $_c $_rev meta nftrace set 1 comment "\"$NX_TAG\"" 2>/dev/null
		else
			echo "$NX_NAME: warning: could not hook chain $_c" >&2
		fi
	done
	[ -n "$NX_INSERTED" ] || nx_die "could not insert any probe rule (check the filter)"
}

# nx_remove_probes <pattern> <chains...>  -> removes every rule whose comment contains the pattern
nx_remove_probes() {
	_pat=$1; shift; _n=0
	for _c in "$@"; do
		for _h in $(nft -a list chain $NX_TABLE_FAM $NX_TABLE $_c 2>/dev/null | grep "$_pat" | grep -oE 'handle [0-9]+' | awk '{print $2}'); do
			nft delete rule $NX_TABLE_FAM $NX_TABLE $_c handle "$_h" 2>/dev/null && _n=$((_n + 1))
		done
	done
	NX_REMOVED=$_n
}

# nx_stream <mode> <json> <chains...>: run the trace until interrupted / timed out, then clean up
nx_stream() {
	_mode=$1; _json=$2; shift 2
	[ -r "$NX_AWK" ] || nx_die "missing $NX_AWK"
	NX_FIFO="/tmp/.$NX_NAME.$$.fifo"; rm -f "$NX_FIFO"; mkfifo "$NX_FIFO" || nx_die "cannot create fifo"
	NX_CLEANED=0
	nx_cleanup() {
		[ "$NX_CLEANED" = 1 ] && return; NX_CLEANED=1
		[ -n "$NX_TRACE_PID" ] && kill "$NX_TRACE_PID" 2>/dev/null
		[ -n "$NX_TIMER_PID" ] && kill "$NX_TIMER_PID" 2>/dev/null
		# let the formatter print the last pending packet (it flushes on EOF), then stop it
		_i=0; while [ -n "$NX_AWK_PID" ] && kill -0 "$NX_AWK_PID" 2>/dev/null && [ $_i -lt 20 ]; do sleep 1 & wait $!; _i=$((_i + 5)); done
		[ -n "$NX_AWK_PID" ] && kill "$NX_AWK_PID" 2>/dev/null
		nx_remove_probes "$NX_TAG" $NX_INSERTED
		rm -f "$NX_FIFO"
		[ "$_json" = 1 ] || echo "$NX_NAME: stopped, probe rules removed"
	}
	trap nx_cleanup EXIT INT TERM HUP
	awk -f "$NX_AWK" -v mode="$_mode" -v json="$_json" -v tool="$NX_NAME" -v marker="$NX_TAG" < "$NX_FIFO" &
	NX_AWK_PID=$!
	nft monitor trace > "$NX_FIFO" 2>/dev/null &
	NX_TRACE_PID=$!
	if [ "${NX_TIMEOUT:-0}" -gt 0 ] 2>/dev/null; then ( sleep "$NX_TIMEOUT"; kill -TERM $$ ) & NX_TIMER_PID=$!; fi
	wait "$NX_AWK_PID"
}
