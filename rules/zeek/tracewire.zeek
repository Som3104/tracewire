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

# failed or half-open TCP connections are scan evidence (states S0, REJ, RSTOS0, SH)
event connection_state_remove(c: connection)
    {
    if ( ! c?$conn || c$conn$proto != tcp ) return;
    if ( c$conn$conn_state !in set("S0", "REJ", "RSTOS0", "SH") ) return;
    SumStats::observe("tw.scan",
                      [$str=fmt("%s->%s", c$id$orig_h, c$id$resp_h)],
                      [$num=port_to_count(c$id$resp_p)]);
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| >= 60 )
        NOTICE([$note=Long_DNS_Query, $conn=c,
                $msg=fmt("DNS query of %d chars: %s", |query|, query),
                $identifier=cat(c$id$orig_h), $suppress_for=60 secs]);
    }
