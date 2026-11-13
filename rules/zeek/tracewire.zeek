##! Tracewire detections for Zeek 6.x
##! Run:  zeek -C -r data/day2.pcap rules/zeek/tracewire.zeek
##! Raises notices in notice.log. Unlike Suricata, Zeek's SumStats can count
##! *distinct* ports per (scanner, victim), which matches rule TW-1001 exactly.

@load base/frameworks/sumstats
@load base/frameworks/notice

module Tracewire;

export {
    redef enum Notice::Type += { Vertical_Scan, Long_DNS_Query };
    const scan_ports_threshold = 20.0 &redef;
    const scan_window = 10 secs &redef;
}

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="tw.scan", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="tw-vertical-scan",
                      $epoch=scan_window,
                      $reducers=set(r1),
                      $threshold=scan_ports_threshold,
                      # Without an epoch_result callback, SumStats' do_finish_epoch() returns
                      # early: counts are never reset and the next epoch is never scheduled,
                      # so the "10 s" window silently becomes the whole capture.
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = { },
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          { return result["tw.scan"]$unique + 0.0; },
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=Vertical_Scan,
                                  $msg=fmt("%s probed %d ports on one host in %s", key$str,
                                           result["tw.scan"]$unique, scan_window),
                                  $identifier=key$str]);
                          }]);
    }

# Scan evidence = a TCP connection whose handshake never completed (no originator ACK).
# Observe it when the failure happens: connection_state_remove fires only when Zeek
# expires the connection, in delayed batches, which would break the 10 s window and
# make a slow scan look fast.
function observe_failed(c: connection)
    {
    if ( get_port_transport_proto(c$id$resp_p) != tcp ) return;
    if ( c?$history && /A/ in c$history ) return;
    SumStats::observe("tw.scan",
                      [$str=fmt("%s->%s", c$id$orig_h, c$id$resp_h)],
                      [$num=port_to_count(c$id$resp_p)]);
    }

event connection_rejected(c: connection) { observe_failed(c); }   # SYN answered by RST ("Sr")
event connection_attempt(c: connection)  { observe_failed(c); }   # SYN never answered ("S")
event connection_reset(c: connection)    { observe_failed(c); }   # SYN-ACK then scanner RST ("ShR")

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| >= 60 )
        NOTICE([$note=Long_DNS_Query, $conn=c,
                $msg=fmt("DNS query of %d chars: %s", |query|, query),
                $identifier=cat(c$id$orig_h), $suppress_for=60 secs]);
    }
