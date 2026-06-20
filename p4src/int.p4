"""
  In-band Network Telemetry (INT) - P4_16 Implementation
  Target: BMv2 simple_switch

  Architecture:
    - INT Source Node  : stamps packets with INT header + metadata
    - INT Transit Node : appends its own hop-level metadata
    - INT Sink Node    : strips INT headers, mirrors report to collector

  Metadata collected per-hop:
    [1] Switch ID
    [2] Ingress + Egress Port IDs
    [3] Hop Latency (nanoseconds)
    [4] Queue Occupancy
    [5] Ingress Timestamp
    [6] Egress Timestamp
    [7] Queue Congestion Status
    [8] Egress Port TX Utilization
 """

#include <core.p4>
#include <v1model.p4>


/* CONSTANTS
 * -----------*/
const bit<16> TYPE_IPV4      = 0x0800;
const bit<8>  PROTO_TCP      = 6;
const bit<8>  PROTO_UDP      = 17;
const bit<8>  PROTO_INT_SHIM = 0xFD;   /* Experimental - INT over UDP/TCP */

const bit<8>  INT_TYPE_HOP_BY_HOP = 1;
const bit<4>  INT_VERSION          = 0;

/* INT Instruction Bitmap positions */
const bit<16> INT_SWITCH_ID_MASK      = 0x8000;
const bit<16> INT_PORT_IDS_MASK       = 0x4000;
const bit<16> INT_HOP_LATENCY_MASK    = 0x2000;
const bit<16> INT_QUEUE_OCC_MASK      = 0x1000;
const bit<16> INT_INGRESS_TSTAMP_MASK = 0x0800;
const bit<16> INT_EGRESS_TSTAMP_MASK  = 0x0400;
const bit<16> INT_QUEUE_CONG_MASK     = 0x0200;
const bit<16> INT_EGRESS_TX_MASK      = 0x0100;

const bit<32> REPORT_MIRROR_SESSION   = 500;
const bit<16> COLLECTOR_UDP_PORT      = 54321;

/* v1model doesn't export this as a named constant - the value is part
 * of the architecture's fixed ABI (NORMAL=0, INGRESS_CLONE=1, EGRESS_CLONE=2, ...) */
const bit<32> PKT_INSTANCE_TYPE_INGRESS_CLONE = 1;

/* Fixed INT overhead added once at the source: shim(4B) + header(8B) + tail(4B) */
const bit<16> INT_FIXED_OVERHEAD_BYTES = 16;


/* HEADERS
 * -----------*/

/* Standard Ethernet */
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

/* Standard IPv4 */
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

/* TCP */
header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

/* UDP */
header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}


/* INT Shim Header (inserted between L4 and payload)
 * Signals to downstream nodes that packet carries INT data
 * ----------------------------------------------------------*/
header int_shim_t {
    bit<8>  int_type;        /* 1 = hop-by-hop */
    bit<8>  rsvd1;
    bit<8>  length;          /* total INT header length in 4-byte words */
    bit<8>  orig_dscp;       /* original DSCP value before INT marking */
}


/* INT Header (Metadata Stack Header)
 * ---------------------------------------*/
header int_header_t {
    bit<4>  ver;
    bit<2>  rep;
    bit<1>  c_bit;           /* copy flag */
    bit<1>  e_bit;           /* max hop count exceeded */
    bit<1>  m_bit;           /* MTU exceeded */
    bit<7>  rsvd1;
    bit<3>  rsvd2;
    bit<5>  hop_metadata_len; /* words per hop */
    bit<8>  remaining_hop_cnt;
    bit<16> instruction_mask; /* which metadata fields to collect */
    bit<16> rsvd3;
}


/* INT Metadata (per-hop, appended by each transit switch)
 * Each field is present only if corresponding instruction bit=1
 * ---------------------------------------------------------------- */
header int_switch_id_t {
    bit<32> switch_id;
}

header int_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}

header int_hop_latency_t {
    bit<32> hop_latency;     /* nanoseconds */
}

header int_q_occupancy_t {
    bit<8>  q_id;
    bit<24> q_occupancy;     /* bytes */
}

header int_ingress_tstamp_t {
    bit<64> ingress_tstamp;  /* nanoseconds since epoch */
}

header int_egress_tstamp_t {
    bit<64> egress_tstamp;
}

header int_q_congestion_t {
    bit<8>  q_id;
    bit<24> q_congestion;
}

header int_egress_tx_util_t {
    bit<32> egress_tx_util;  /* bits per second utilization */
}


/* INT Tail Header (marks end of INT stack, before payload)
 * -----------------------------------------------------------*/
header int_tail_t {
    bit<8>  next_proto;      /* original protocol above shim */
    bit<16> dest_port;       /* destination port of original flow */
    bit<8>  dscp;
}

/* Telemetry Report Headers (sent to collector)
 * ------------------------------------------------------*/
header report_group_header_t {
    bit<4>  ver;
    bit<4>  hw_id;
    bit<32> seq_no;
    bit<32> node_id;
}

header report_individual_header_t {
    bit<4>  rep_type;
    bit<4>  in_type;
    bit<1>  dropped;
    bit<1>  congested_queue;
    bit<1>  path_tracking_flow;
    bit<5> rsvd;
    bit<16> hw_id;
}


/* HEADER STACK - supports up to 6 hops
 * -------------------------------------*/
struct headers_t {
    /* Outer encapsulation used ONLY for the cloned report sent to the
     * collector. Invalid (and therefore zero bytes on the wire) for
     * every ordinary packet. */
    ethernet_t               report_eth;
    ipv4_t                   report_ipv4;
    udp_t                    report_udp;
    report_group_header_t    report_group_hdr;
    report_individual_header_t report_individual_hdr;

    ethernet_t               ethernet;
    ipv4_t                   ipv4;
    tcp_t                    tcp;
    udp_t                    udp;

    /* INT headers */
    int_shim_t               int_shim;
    int_header_t             int_header;

    /* Hop metadata (up to 6 hops worth) */
    int_switch_id_t[6]       int_switch_id;
    int_port_ids_t[6]        int_port_ids;
    int_hop_latency_t[6]     int_hop_latency;
    int_q_occupancy_t[6]     int_q_occupancy;
    int_ingress_tstamp_t[6]  int_ingress_tstamp;
    int_egress_tstamp_t[6]   int_egress_tstamp;
    int_q_congestion_t[6]    int_q_congestion;
    int_egress_tx_util_t[6]  int_egress_tx_util;

    int_tail_t                int_tail;
}


/* METADATA
 * -----------------*/
struct int_metadata_t {
    bit<1>  source;           /* this switch is INT source */
    bit<1>  sink;             /* this switch is INT sink */
    bit<1>  transit;          /* this switch is INT transit */
    bit<32> switch_id;
    bit<16> insert_byte_cnt;  /* bytes added this hop */
    bit<8>  int_hdr_word_len;
    bit<32> hop_latency;
    bit<16> flow_id;
}

struct metadata_t {
    int_metadata_t   int_meta;
    bit<16>          l4_src_port;
    bit<16>          l4_dst_port;
    bit<9>           ingress_port;
    bit<9>           egress_port;
    bit<48>          ingress_tstamp;
    bit<48>          egress_tstamp;

    /* Parser bookkeeping: 4-byte words of hop metadata still left to
     * parse for the hops that already traversed this packet. */
    bit<16>          parse_words_left;

    /* Telemetry-report fields. These are part of the same struct that
     * gets passed whole to clone3(), so whatever is written here during
     * ingress is exactly what the cloned report packet will see. */
    bit<48>          report_switch_mac;
    bit<32>          report_switch_ip;
    bit<48>          report_collector_mac;
    bit<32>          report_collector_ip;
    bit<16>          report_collector_port;
    bit<32>          report_seq_no;
}



/* PARSER
 * -----------*/
parser IntParser(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t smeta
) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        /* Capture ingress timestamp from standard metadata */
        meta.ingress_tstamp = smeta.ingress_global_timestamp;
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP:      parse_tcp;
            PROTO_UDP:      parse_udp;
            PROTO_INT_SHIM: parse_int_shim;
            default:        accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.l4_src_port = hdr.tcp.src_port;
        meta.l4_dst_port = hdr.tcp.dst_port;
        /* Check DSCP for INT marking (DSCP = 0x17 means INT-enabled flow) */
        transition select(hdr.ipv4.diffserv) {
            
            default:        accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.l4_src_port = hdr.udp.src_port;
        meta.l4_dst_port = hdr.udp.dst_port;
        transition select(hdr.ipv4.diffserv) {
            
            default:        accept;
        }
    }

    state parse_int_shim {
        packet.extract(hdr.int_shim);
        transition parse_int_header;
    }

    state parse_int_header {
        packet.extract(hdr.int_header);
        /* hdr.int_shim.length is the cumulative metadata word-count
         * already inserted by every hop this packet has passed through
         * so far. We must consume exactly that many words before we
         * reach int_tail / the original payload. */
        meta.parse_words_left = (bit<16>) hdr.int_shim.length;
        transition parse_int_hop;
    }

    /* Loop entry: one iteration per hop already on the wire. */
    state parse_int_hop {
        transition select(meta.parse_words_left) {
            0:       parse_int_tail;
            default: parse_int_hop_switch_id;
        }
    }

    state parse_int_hop_switch_id {
        transition select(hdr.int_header.instruction_mask & INT_SWITCH_ID_MASK) {
            0:       parse_int_hop_port_ids;
            default: parse_int_hop_switch_id_extract;
        }
    }
    state parse_int_hop_switch_id_extract {
        packet.extract(hdr.int_switch_id.next);
        meta.parse_words_left = meta.parse_words_left - 1;
        transition parse_int_hop_port_ids;
    }

    state parse_int_hop_port_ids {
        transition select(hdr.int_header.instruction_mask & INT_PORT_IDS_MASK) {
            0:       parse_int_hop_hop_latency;
            default: parse_int_hop_port_ids_extract;
        }
    }
    state parse_int_hop_port_ids_extract {
        packet.extract(hdr.int_port_ids.next);
        meta.parse_words_left = meta.parse_words_left - 1;
        transition parse_int_hop_hop_latency;
    }

    state parse_int_hop_hop_latency {
        transition select(hdr.int_header.instruction_mask & INT_HOP_LATENCY_MASK) {
            0:       parse_int_hop_q_occupancy;
            default: parse_int_hop_hop_latency_extract;
        }
    }
    state parse_int_hop_hop_latency_extract {
        packet.extract(hdr.int_hop_latency.next);
        meta.parse_words_left = meta.parse_words_left - 1;
        transition parse_int_hop_q_occupancy;
    }

    state parse_int_hop_q_occupancy {
        transition select(hdr.int_header.instruction_mask & INT_QUEUE_OCC_MASK) {
            0:       parse_int_hop_ingress_tstamp;
            default: parse_int_hop_q_occupancy_extract;
        }
    }
    state parse_int_hop_q_occupancy_extract {
        packet.extract(hdr.int_q_occupancy.next);
        meta.parse_words_left = meta.parse_words_left - 1;
        transition parse_int_hop_ingress_tstamp;
    }

    state parse_int_hop_ingress_tstamp {
        transition select(hdr.int_header.instruction_mask & INT_INGRESS_TSTAMP_MASK) {
            0:       parse_int_hop_egress_tstamp;
            default: parse_int_hop_ingress_tstamp_extract;
        }
    }
    state parse_int_hop_ingress_tstamp_extract {
        packet.extract(hdr.int_ingress_tstamp.next);
        meta.parse_words_left = meta.parse_words_left - 2; /* 8 bytes */
        transition parse_int_hop_egress_tstamp;
    }

    state parse_int_hop_egress_tstamp {
        transition select(hdr.int_header.instruction_mask & INT_EGRESS_TSTAMP_MASK) {
            0:       parse_int_hop;            /* loop back for next hop */
            default: parse_int_hop_egress_tstamp_extract;
        }
    }
    state parse_int_hop_egress_tstamp_extract {
        packet.extract(hdr.int_egress_tstamp.next);
        meta.parse_words_left = meta.parse_words_left - 2; /* 8 bytes */
        transition parse_int_hop;              /* loop back for next hop */
    }

    state parse_int_tail {
        packet.extract(hdr.int_tail);
        transition accept;
    }
}


/* CHECKSUM VERIFICATION
 * -------------------------- */
control IntVerifyChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.total_len, hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl,
                hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}


/* INGRESS PIPELINE
 * ------------------*/
control IntIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t smeta
) {
    /* ---- Counters ------------------------------------ */
    counter(1024, CounterType.packets_and_bytes) ingress_pkt_counter;
    counter(1024, CounterType.packets_and_bytes) int_pkt_counter;

    /* ---- Actions ---------------------------------------- */

    /* Standard IPv4 forwarding */
    action ipv4_forward(bit<48> dst_mac, bit<9> port) {
        smeta.egress_spec = port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action drop_packet() {
        mark_to_drop(smeta);
    }

    /* Mark this switch as INT SOURCE - initiates INT header insertion */
    action int_set_source() {
        meta.int_meta.source = 1;
    }

    /* Mark this switch as INT SINK - strips headers, generates report */
    action int_set_sink(bit<32> switch_id) {
        meta.int_meta.sink     = 1;
        meta.int_meta.switch_id = switch_id;
    }

    /* Mark as TRANSIT - appends metadata, passes along */
    action int_set_transit(bit<32> switch_id) {
        meta.int_meta.transit   = 1;
        meta.int_meta.switch_id = switch_id;
    }

    /* Identity used to build the outer report packet sent to the collector.
     * Only ever installed (matched on sink==1) for the switch acting as
     * the INT sink for a given flow. */
    action int_set_report_config(bit<48> switch_mac, bit<32> switch_ip,
                                  bit<48> collector_mac, bit<32> collector_ip,
                                  bit<16> collector_port) {
        meta.report_switch_mac     = switch_mac;
        meta.report_switch_ip      = switch_ip;
        meta.report_collector_mac  = collector_mac;
        meta.report_collector_ip   = collector_ip;
        meta.report_collector_port = collector_port;
    }

    register<bit<32>>(1) report_seq_reg;

    /* ---- Tables ---------------------------------------- */

    /* IPv4 Forwarding Table */
    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            drop_packet;
            NoAction;
        }
        size = 1024;
        default_action = drop_packet();
    }

    /* INT Source Table - which flows should have INT initiated */
    table int_source_table {
        key = {
            hdr.ipv4.src_addr:  ternary;
            hdr.ipv4.dst_addr:  ternary;
            meta.l4_src_port:   ternary;
            meta.l4_dst_port:   ternary;
        }
        actions = {
            int_set_source;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    /* INT Sink Table - which egress ports lead to non-INT domains */
    table int_sink_table {
        key = {
            smeta.egress_spec: exact;
        }
        actions = {
            int_set_sink;
            NoAction;
        }
        size = 64;
        default_action = NoAction();
    }

    /* INT Transit Role assignment */
    table int_transit_table {
        key = {
            hdr.int_shim.isValid(): exact;
        }
        actions = {
            int_set_transit;
            NoAction;
        }
        size = 2;
        default_action = NoAction();
    }

    /* Report-encapsulation identity, only populated where int_sink_table
     * actually fires (sink == 1) for this switch. */
    table int_report_config {
        key = {
            meta.int_meta.sink: exact;
        }
        actions = {
            int_set_report_config;
            NoAction;
        }
        size = 2;
        default_action = NoAction();
    }

    apply {
        /* Count all ingress packets */
        ingress_pkt_counter.count((bit<32>) smeta.ingress_port);

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();

            /* Determine INT role for this switch */
            if (hdr.int_shim.isValid()) {
                /* Packet already has INT - we are transit or sink */
                int_transit_table.apply();
                int_sink_table.apply();
                int_pkt_counter.count((bit<32>) smeta.ingress_port);

                if (meta.int_meta.sink == 1) {
                    /* Request the telemetry-report clone now, in ingress.
                     * BMv2's I2E clone snapshots the packet as it looked
                     * when it MOST RECENTLY ENTERED ingress - i.e. before
                     * this switch's own changes, including the header
                     * strip that happens later in egress. An egress
                     * (E2E) clone would NOT work here: its snapshot is
                     * taken at the end of egress processing, by which
                     * point the strip has already happened, so the
                     * "report" would arrive at the collector empty. */
                    int_report_config.apply();
                    report_seq_reg.read(meta.report_seq_no, 0);
                    report_seq_reg.write(0, meta.report_seq_no + 1);
                    clone3(CloneType.I2E, REPORT_MIRROR_SESSION, meta);
                }
            } else {
                /* Check if this flow should have INT initiated */
                int_source_table.apply();
            }
        }

        /* Capture ingress port for metadata. NOTE: enq_qdepth /
         * deq_qdepth / deq_timedelta are intentionally NOT copied here -
         * those queueing-metadata fields are only valid once a packet
         * has actually been enqueued/dequeued, i.e. from egress onward.
         * Reading them in ingress always returns 0. The egress actions
         * below read smeta.deq_timedelta / smeta.deq_qdepth directly. */
        meta.ingress_port = smeta.ingress_port;
    }
}


/* EGRESS PIPELINE  ← This is where the INT magic happens
* --------------------------------------------------------------*/
control IntEgress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t smeta
) {
    /* ---- INT Source Actions ----------------------------------- */

    /* Insert the INT shim + INT header into the packet */
    action int_source_add_shim() {
        hdr.int_shim.setValid();
        hdr.int_shim.int_type  = INT_TYPE_HOP_BY_HOP;
        hdr.int_shim.length    = 0;  /* updated after metadata insertion */
        hdr.int_shim.orig_dscp = hdr.ipv4.diffserv >> 2;

        hdr.int_header.setValid();
        hdr.int_header.ver               = INT_VERSION;
        hdr.int_header.rep               = 0;
        hdr.int_header.c_bit             = 0;
        hdr.int_header.e_bit             = 0;
        hdr.int_header.m_bit             = 0;
        /* words per hop with mask 0xFC00 (6 fields): switch_id(1) +
         * port_ids(1) + hop_latency(1) + queue_occ(1) +
         * ingress_tstamp(2) + egress_tstamp(2) = 8 words */
        hdr.int_header.hop_metadata_len  = 8;
        hdr.int_header.remaining_hop_cnt = 6; /* max 6 hops */
        /* Collect: Switch ID, Port IDs, Hop Latency, Queue Occ, both Timestamps */
        hdr.int_header.instruction_mask  = 0xFC00;

        hdr.int_tail.setValid();
        hdr.int_tail.next_proto = hdr.ipv4.protocol;
        hdr.int_tail.dest_port  = meta.l4_dst_port;
        hdr.int_tail.dscp       = hdr.int_shim.orig_dscp;

        /* CRITICAL: IntParser's parse_ipv4 state branches on
         * hdr.ipv4.protocol to decide whether to even look for an INT
         * shim at all. Without rewriting it here, every switch after
         * this one would see the original TCP/UDP protocol number,
         * skip straight into parse_tcp/parse_udp, and never reach the
         * int_shim/int_header/metadata parser states - the entire INT
         * stack would be silently misparsed as L4 + payload bytes by
         * every downstream switch. */
        hdr.ipv4.protocol = PROTO_INT_SHIM;

        /* Fixed overhead added once at the source: shim + header + tail.
         * Per-hop metadata growth is tracked separately below. */
        hdr.ipv4.total_len = hdr.ipv4.total_len + INT_FIXED_OVERHEAD_BYTES;

        /* Mark packet with INT DSCP */
        hdr.ipv4.diffserv = 0x5C;
    }

    /* ---- INT Transit Actions ---------------------------------- */

    /* Append Switch ID */
    action int_transit_add_switch_id() {
        hdr.int_switch_id.push_front(1);
        hdr.int_switch_id[0].setValid();
        hdr.int_switch_id[0].switch_id = meta.int_meta.switch_id;
        meta.int_meta.insert_byte_cnt  = meta.int_meta.insert_byte_cnt + 4;
    }

    /* Append Port IDs */
    action int_transit_add_port_ids() {
        hdr.int_port_ids.push_front(1);
        hdr.int_port_ids[0].setValid();
        hdr.int_port_ids[0].ingress_port_id = (bit<16>) meta.ingress_port;
        hdr.int_port_ids[0].egress_port_id  = (bit<16>) smeta.egress_port;
        meta.int_meta.insert_byte_cnt        = meta.int_meta.insert_byte_cnt + 4;
    }

    /* Append Hop Latency = dequeue_timedelta (ns spent in this switch).
     * Read directly from standard_metadata: this is only valid in
     * egress (queueing happens between ingress and egress), so going
     * through a meta.* copy made in ingress always read back as 0. */
    action int_transit_add_hop_latency() {
        hdr.int_hop_latency.push_front(1);
        hdr.int_hop_latency[0].setValid();
        hdr.int_hop_latency[0].hop_latency = smeta.deq_timedelta;
        meta.int_meta.insert_byte_cnt       = meta.int_meta.insert_byte_cnt + 4;
    }

    /* Append Queue Occupancy - same reasoning, read smeta directly. */
    action int_transit_add_q_occupancy() {
        hdr.int_q_occupancy.push_front(1);
        hdr.int_q_occupancy[0].setValid();
        hdr.int_q_occupancy[0].q_id         = 0;
        hdr.int_q_occupancy[0].q_occupancy  = (bit<24>) smeta.deq_qdepth;
        meta.int_meta.insert_byte_cnt        = meta.int_meta.insert_byte_cnt + 4;
    }

    /* Append Ingress Timestamp */
    action int_transit_add_ingress_tstamp() {
        hdr.int_ingress_tstamp.push_front(1);
        hdr.int_ingress_tstamp[0].setValid();
        hdr.int_ingress_tstamp[0].ingress_tstamp = (bit<64>) meta.ingress_tstamp;
        meta.int_meta.insert_byte_cnt             = meta.int_meta.insert_byte_cnt + 8;
    }

    /* Append Egress Timestamp */
    action int_transit_add_egress_tstamp() {
        hdr.int_egress_tstamp.push_front(1);
        hdr.int_egress_tstamp[0].setValid();
        hdr.int_egress_tstamp[0].egress_tstamp = (bit<64>) meta.egress_tstamp;
        meta.int_meta.insert_byte_cnt           = meta.int_meta.insert_byte_cnt + 8;
    }

    /* ---- INT Sink Actions ----------------------------------- */

    /* Strip all INT headers, restore original DSCP */
    action int_sink_remove_headers() {
        hdr.ipv4.diffserv = hdr.int_shim.orig_dscp << 2;
        /* Restore the real L4 protocol number that the source saved
         * off before overwriting it with PROTO_INT_SHIM. Must happen
         * before int_tail is invalidated below. */
        hdr.ipv4.protocol = hdr.int_tail.next_proto;

        /* Invalidate all INT header stacks */
        hdr.int_shim.setInvalid();
        hdr.int_header.setInvalid();

        /* Remove collected metadata */
        hdr.int_switch_id[0].setInvalid();
        hdr.int_switch_id[1].setInvalid();
        hdr.int_switch_id[2].setInvalid();
        hdr.int_switch_id[3].setInvalid();
        hdr.int_switch_id[4].setInvalid();
        hdr.int_switch_id[5].setInvalid();

        hdr.int_port_ids[0].setInvalid();
        hdr.int_port_ids[1].setInvalid();
        hdr.int_port_ids[2].setInvalid();
        hdr.int_port_ids[3].setInvalid();
        hdr.int_port_ids[4].setInvalid();
        hdr.int_port_ids[5].setInvalid();

        hdr.int_hop_latency[0].setInvalid();
        hdr.int_hop_latency[1].setInvalid();
        hdr.int_hop_latency[2].setInvalid();
        hdr.int_hop_latency[3].setInvalid();
        hdr.int_hop_latency[4].setInvalid();
        hdr.int_hop_latency[5].setInvalid();

        hdr.int_q_occupancy[0].setInvalid();
        hdr.int_q_occupancy[1].setInvalid();
        hdr.int_q_occupancy[2].setInvalid();
        hdr.int_q_occupancy[3].setInvalid();
        hdr.int_q_occupancy[4].setInvalid();
        hdr.int_q_occupancy[5].setInvalid();

        hdr.int_ingress_tstamp[0].setInvalid();
        hdr.int_ingress_tstamp[1].setInvalid();
        hdr.int_ingress_tstamp[2].setInvalid();
        hdr.int_ingress_tstamp[3].setInvalid();
        hdr.int_ingress_tstamp[4].setInvalid();
        hdr.int_ingress_tstamp[5].setInvalid();

        hdr.int_egress_tstamp[0].setInvalid();
        hdr.int_egress_tstamp[1].setInvalid();
        hdr.int_egress_tstamp[2].setInvalid();
        hdr.int_egress_tstamp[3].setInvalid();
        hdr.int_egress_tstamp[4].setInvalid();
        hdr.int_egress_tstamp[5].setInvalid();

        hdr.int_q_congestion[0].setInvalid();
        hdr.int_q_congestion[1].setInvalid();
        hdr.int_q_congestion[2].setInvalid();
        hdr.int_q_congestion[3].setInvalid();
        hdr.int_q_congestion[4].setInvalid();
        hdr.int_q_congestion[5].setInvalid();

        hdr.int_egress_tx_util[0].setInvalid();
        hdr.int_egress_tx_util[1].setInvalid();
        hdr.int_egress_tx_util[2].setInvalid();
        hdr.int_egress_tx_util[3].setInvalid();
        hdr.int_egress_tx_util[4].setInvalid();
        hdr.int_egress_tx_util[5].setInvalid();

        hdr.int_tail.setInvalid();
    }

    apply {
        meta.egress_port   = smeta.egress_port;
        meta.egress_tstamp = smeta.egress_global_timestamp;

        if (smeta.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
            /* This is the cloned copy created by clone3(I2E, ...) in
             * IntIngress, on its way to the collector. hdr still holds
             * the packet exactly as it looked on arrival at the sink
             * (full INT stack, untouched) - we do NOT want to run any
             * of the normal source/transit/sink logic again on it
             * (that would double-add metadata and, since meta.int_meta
             * .sink is also preserved as 1, would re-request another
             * clone of this clone). Instead, just wrap it in the
             * outer report headers built entirely from the metadata
             * fields preserved by clone3 - never from hdr, since hdr's
             * validity bits were captured before this switch did
             * anything, and the report config table only runs in
             * ingress.
             */
            hdr.report_eth.setValid();
            hdr.report_eth.dst_addr   = meta.report_collector_mac;
            hdr.report_eth.src_addr   = meta.report_switch_mac;
            hdr.report_eth.ether_type = TYPE_IPV4;

            hdr.report_ipv4.setValid();
            hdr.report_ipv4.version        = 4;
            hdr.report_ipv4.ihl            = 5;
            hdr.report_ipv4.diffserv       = 0;
            hdr.report_ipv4.identification = 0;
            hdr.report_ipv4.flags          = 0;
            hdr.report_ipv4.frag_offset    = 0;
            hdr.report_ipv4.ttl            = 64;
            hdr.report_ipv4.protocol       = PROTO_UDP;
            hdr.report_ipv4.src_addr       = meta.report_switch_ip;
            hdr.report_ipv4.dst_addr       = meta.report_collector_ip;
            hdr.report_ipv4.hdr_checksum   = 0; /* recomputed by IntComputeChecksum */
            /* outer IP hdr(20) + outer UDP hdr(8) + report headers(13)
             * + inner ethernet(14) + inner IP packet (already includes
             * the INT overhead) */
            hdr.report_ipv4.total_len      = 20 + 8 + 9 + 4 + 14 + hdr.ipv4.total_len;

            hdr.report_udp.setValid();
            hdr.report_udp.src_port = 9999;
            hdr.report_udp.dst_port = meta.report_collector_port;
            hdr.report_udp.length   = 8 + 9 + 4 + 14 + hdr.ipv4.total_len;
            hdr.report_udp.checksum = 0; /* optional for IPv4; left unset */

            hdr.report_group_hdr.setValid();
            hdr.report_group_hdr.ver     = 0;
            hdr.report_group_hdr.hw_id   = 0;
            hdr.report_group_hdr.seq_no  = meta.report_seq_no;
            hdr.report_group_hdr.node_id = meta.int_meta.switch_id;

            hdr.report_individual_hdr.setValid();
            hdr.report_individual_hdr.rep_type          = 0;
            hdr.report_individual_hdr.in_type            = INT_TYPE_HOP_BY_HOP;
            hdr.report_individual_hdr.dropped             = 0;
            hdr.report_individual_hdr.congested_queue     = 0;
            hdr.report_individual_hdr.path_tracking_flow  = 0;
            hdr.report_individual_hdr.rsvd                = 0;
            hdr.report_individual_hdr.hw_id               = (bit<16>) meta.int_meta.switch_id;

        } else {
            /* === Normal (non-clone) packet processing === */

            if (meta.int_meta.source == 1) {
                /* === SOURCE NODE === */
                int_source_add_shim();
            }

            if (hdr.int_shim.isValid() &&
                hdr.int_header.remaining_hop_cnt > 0) {
                /* === TRANSIT NODE (or source after shim added) === */

                /* Decrement remaining hop count */
                hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;

                /* Reset byte counter for this hop */
                meta.int_meta.insert_byte_cnt = 0;

                /* Add metadata according to instruction bitmap */
                if ((hdr.int_header.instruction_mask & INT_SWITCH_ID_MASK) != 0) {
                    int_transit_add_switch_id();
                }
                if ((hdr.int_header.instruction_mask & INT_PORT_IDS_MASK) != 0) {
                    int_transit_add_port_ids();
                }
                if ((hdr.int_header.instruction_mask & INT_HOP_LATENCY_MASK) != 0) {
                    int_transit_add_hop_latency();
                }
                if ((hdr.int_header.instruction_mask & INT_QUEUE_OCC_MASK) != 0) {
                    int_transit_add_q_occupancy();
                }
                if ((hdr.int_header.instruction_mask & INT_INGRESS_TSTAMP_MASK) != 0) {
                    int_transit_add_ingress_tstamp();
                }
                if ((hdr.int_header.instruction_mask & INT_EGRESS_TSTAMP_MASK) != 0) {
                    int_transit_add_egress_tstamp();
                }

                /* Update IPv4 total_len to account for inserted bytes */
                hdr.ipv4.total_len = hdr.ipv4.total_len + meta.int_meta.insert_byte_cnt;

                /* Update shim length (in 4-byte words) */
                hdr.int_shim.length = hdr.int_shim.length +
                    (bit<8>)(meta.int_meta.insert_byte_cnt >> 2);
            }

            if (meta.int_meta.sink == 1 && hdr.int_shim.isValid()) {
                /* === SINK NODE ===
                 * The report clone was already requested back in
                 * ingress (see IntIngress) - here we only strip the
                 * INT stack so the packet h2 actually receives is
                 * clean. */
                int_sink_remove_headers();
            }
        }
    }
}

/* CHECKSUM UPDATE
 * ------------------*/
control IntComputeChecksum(
    inout headers_t hdr,
    inout metadata_t meta
) {
    apply {
        update_checksum(
            hdr.report_ipv4.isValid(),
            {
                hdr.report_ipv4.version, hdr.report_ipv4.ihl, hdr.report_ipv4.diffserv,
                hdr.report_ipv4.total_len, hdr.report_ipv4.identification,
                hdr.report_ipv4.flags, hdr.report_ipv4.frag_offset, hdr.report_ipv4.ttl,
                hdr.report_ipv4.protocol, hdr.report_ipv4.src_addr, hdr.report_ipv4.dst_addr
            },
            hdr.report_ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.total_len, hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl,
                hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16
        );
    }
}


/* DEPARSER
 * -----------*/
control IntDeparser(
    packet_out packet,
    in headers_t hdr
) {
    apply {
        /* Outer report encapsulation. For every ordinary packet these
         * headers were never set valid, so emit() writes zero bytes -
         * this block only produces output for the cloned report copy. */
        packet.emit(hdr.report_eth);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_group_hdr);
        packet.emit(hdr.report_individual_hdr);

        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);

        /* Emit metadata HOP-MAJOR (all fields for the most recent hop,
         * then all fields for the next hop back, ...) so the byte
         * layout matches IntParser's parse_int_hop_* loop on the next
         * switch, and matches IntReportDecoder.decode() in the
         * controller. Each stack index is emitted explicitly (no
         * native loops in a P4_16 deparser); emitting an invalid
         * header costs 0 bytes, so hops beyond the actual hop count
         * simply contribute nothing. */
        packet.emit(hdr.int_switch_id[0]);
        packet.emit(hdr.int_port_ids[0]);
        packet.emit(hdr.int_hop_latency[0]);
        packet.emit(hdr.int_q_occupancy[0]);
        packet.emit(hdr.int_ingress_tstamp[0]);
        packet.emit(hdr.int_egress_tstamp[0]);

        packet.emit(hdr.int_switch_id[1]);
        packet.emit(hdr.int_port_ids[1]);
        packet.emit(hdr.int_hop_latency[1]);
        packet.emit(hdr.int_q_occupancy[1]);
        packet.emit(hdr.int_ingress_tstamp[1]);
        packet.emit(hdr.int_egress_tstamp[1]);

        packet.emit(hdr.int_switch_id[2]);
        packet.emit(hdr.int_port_ids[2]);
        packet.emit(hdr.int_hop_latency[2]);
        packet.emit(hdr.int_q_occupancy[2]);
        packet.emit(hdr.int_ingress_tstamp[2]);
        packet.emit(hdr.int_egress_tstamp[2]);

        packet.emit(hdr.int_switch_id[3]);
        packet.emit(hdr.int_port_ids[3]);
        packet.emit(hdr.int_hop_latency[3]);
        packet.emit(hdr.int_q_occupancy[3]);
        packet.emit(hdr.int_ingress_tstamp[3]);
        packet.emit(hdr.int_egress_tstamp[3]);

        packet.emit(hdr.int_switch_id[4]);
        packet.emit(hdr.int_port_ids[4]);
        packet.emit(hdr.int_hop_latency[4]);
        packet.emit(hdr.int_q_occupancy[4]);
        packet.emit(hdr.int_ingress_tstamp[4]);
        packet.emit(hdr.int_egress_tstamp[4]);

        packet.emit(hdr.int_switch_id[5]);
        packet.emit(hdr.int_port_ids[5]);
        packet.emit(hdr.int_hop_latency[5]);
        packet.emit(hdr.int_q_occupancy[5]);
        packet.emit(hdr.int_ingress_tstamp[5]);
        packet.emit(hdr.int_egress_tstamp[5]);

        /* Reserved/unimplemented optional fields - always invalid,
         * always 0 bytes; kept for forward compatibility. */
        packet.emit(hdr.int_q_congestion);
        packet.emit(hdr.int_egress_tx_util);

        packet.emit(hdr.int_tail);
    }
}


/* MAIN SWITCH INSTANTIATION
 * ----------------------------- */
V1Switch(
    IntParser(),
    IntVerifyChecksum(),
    IntIngress(),
    IntEgress(),
    IntComputeChecksum(),
    IntDeparser()
) main;
