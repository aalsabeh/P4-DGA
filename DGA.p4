// Initial base code taken from: github.com/hyojoonkim/Meta4

#include <core.p4>
#include <tna.p4>

#define NUM_IPV4_DST_IP 100
#define HOST_MONITOR 110000
#define LABEL_LENGTH_C 56
#define HASH_LENGTH_C 16
#define RECIRCULATE_ID_C 220
#define NXDomain 3
#define DONE_PARSING 30 
#define PARTIAL_LABEL_PARSING 40
#define FULL_LABEL_PARSING 50
#define NUM_STATIC_BIGRAMS 1376
#define MAX_CHARS 8w07

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;
typedef bit<32> BigramVal;

header ethernet_h {
    MacAddress dst;
    MacAddress src;
    bit<16> etherType; 
}
header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> len;
    bit<16> id;
    bit<3> flags;
    bit<13> frag;
    bit<8> ttl;
    bit<8> proto;
    bit<16> chksum;
    IPv4Address src;
    IPv4Address dst; 
}
header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum; 
}
header dns_h {
    bit<16> id;
    bit<1> is_response;
    bit<4> opcode;
    bit<1> auth_answer;
    bit<1> trunc;
    bit<1> recur_desired;
    bit<1> recur_avail;
    bit<1> reserved;
    bit<1> authentic_data;
    bit<1> checking_disabled;
    bit<4> resp_code;
    bit<16> q_count;
    bit<16> answer_count;
    bit<16> auth_rec;
    bit<16> addn_rec;
}
header dns_q_label {
    bit<8> label_len;
}
header dns_q_part_1 {
    bit<8> part;
}
header dns_q_part_2 {
    bit<16> part;
}
header dns_q_part_4 {
    bit<32> part;
}
header dns_q_part_8 {
    bit<64> part;
}
struct dns_qtype_class {
    bit<16> type;
    bit<16> class;
}
header dns_query_tc{
    dns_qtype_class tc_query;
}
header dns_a {
    bit<16> qname_pointer;
    dns_qtype_class tc_ans;
    bit<32> ttl;
    bit<8> rd_length_1;
    bit<8> rd_length_2;
}
header dns_a_ip {
    bit<32> rdata;
}
header recirculate_h {
    bit<8> recirculate_id;
    bit<8> recirculate_bit;
    bit<16> hash_concat_hashes;

    // Context-aware features
    bit<32> dga_ip;
    bit<32> ip_reqs;
    bit<32> dns_reqs;
    bit<32> i_arrival;

    // Context-less features
    BigramVal bigram;
    bit<8> domain_name_length;
    bit<8> num_subdomains;
    bit<16> hash_last_label;
    // bit<8> is_valid_tld;
    // bit<8> has_single_subd;
    // bit<8> num_underscores;
    
    // remainder: used to save the length of the next label
    bit<8> next_label_len;
}

// List of all recognized headers
struct Parsed_packet { 
    recirculate_h recirculate;
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    dns_h dns_header;

    dns_q_label begin_label_len;

    dns_q_label label1;
    dns_q_part_1 q1_part1;
    dns_q_part_2 q1_part2;
    dns_q_part_4 q1_part4;
    dns_q_part_8 q1_part8;

    dns_q_label label2;
    dns_q_part_1 q2_part1;
    dns_q_part_2 q2_part2;
    dns_q_part_4 q2_part4;

    dns_q_label label3;
    dns_q_part_1 q3_part1;
    dns_q_part_2 q3_part2;
    dns_q_part_4 q3_part4;

    dns_q_label label_last;

    dns_query_tc query_tc;

    dns_a dns_answer;
    dns_a_ip dns_ip;

}

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct ig_metadata_t {
    recirculate_h recirculate_metadata; 
    bit<1> is_response;
    bit<1> do_dns;
    bit<1> recur_desired;
    bit<1> response_set;
	bit<1> is_dns;
	bit<1> is_ip;

    bit<3> tld;
    bit<1> partial_parsing;
    bit<1> parsed_dns_query;
    bit<2> is_TLD;

    bit<1> parsed_answer;
    
    bit<8> parsed_labels_len;
    bit<8> next_label_len;

    // Metadata used for implementing the Random Forest, adopted from the paper: Flowrest: Practical Flow-Level Inference in Programmable Switches with Random Forests
    // Link to the paper: https://dspace.networks.imdea.org/bitstream/handle/20.500.12761/1649/Flowrest_INFOCOM_2023_av.pdf?sequence=1&isAllowed=y
    bit<32> feature0;
    bit<32> feature1;
    bit<32> feature2;
    bit<32> feature3;

    bit<32> code0;
    bit<32> code1;
    bit<32> code2;

    bit<8> class0;
    bit<8> class1;
    bit<8> class2;
}
struct eg_metadata_t {
    recirculate_h recirculate_metadata;
    bit<4> is_ip;
    bit<4> is_dns; 
    bit<16> index;
    bit<32> iarrival;
}

struct digest_t {
    bit<32> dga_ip;
    bit<32> ip_reqs;
    bit<32> dns_reqs;
    bit<32> bigram;
    bit<8> domain_name_length;
    bit<8> num_subdomains;
    bit<16> hash_last_label; // tld
    // bit<8> is_valid_tld;
    // bit<8> has_single_subd;
    // bit<8> num_underscores;
}

// parsers
parser SwitchIngressParser(packet_in pkt,
           out Parsed_packet p,
           out ig_metadata_t ig_md,
           out ingress_intrinsic_metadata_t ig_intr_md) {

    ParserCounter() parse_limit;
    ParserCounter() is_recirc_char;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(64);
        bit<8> recirculate_id = pkt.lookahead<bit<8>>();
    
        transition select(recirculate_id){
            // If the first 8 bits is 220, then it's a recirculated packet
            RECIRCULATE_ID_C: parse_recirculate; 
            _: parse_ethernet;
        }
    }
    state parse_recirculate {
        pkt.extract(p.recirculate);
        transition select(p.recirculate.recirculate_bit){
            DONE_PARSING: accept;
            default: parse_ethernet;
        }
    }
    state parse_ethernet {
        pkt.extract(p.ethernet);
        ig_md.do_dns = 0;
        ig_md.recur_desired = 0;
        ig_md.response_set = 0;
		ig_md.is_dns = 0;
		ig_md.is_ip = 0;
        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }
	state parse_ip {
        pkt.extract(p.ipv4);
		ig_md.is_ip = 1;
        ig_md.is_dns = 0;
		transition select(p.ipv4.proto) {
			17: parse_udp;
			default: accept;
		}
	}
    state parse_udp {
        pkt.extract(p.udp);
		transition select(p.udp.dport) {
			53: parse_dns_header;
			default: parse_udp_2;
		}
	}
	state parse_udp_2 {
		transition select(p.udp.sport) {
			53: parse_dns_header;
			default: accept;
        }
    }
	state parse_dns_header {
        pkt.extract(p.dns_header);
		ig_md.is_dns = 1;
        parse_limit.set(MAX_CHARS);
        is_recirc_char.set(8w00);
		transition select(p.dns_header.is_response) {
            0: is_request_state;
            1: is_reponse_state;
			default: accept;
		}
	}
    state is_request_state {
        ig_md.is_response = 0;
        transition accept;
    }
    state is_reponse_state {
        ig_md.is_response = 1;
        transition parse_dns_query1;
    }

    state parse_dns_query1 {
        pkt.extract(p.label1);
        transition select(p.label1.label_len) {
            0: parse_query_tc;
            1: parse_dns_q1_len1;
            2: parse_dns_q1_len2;
            3: parse_dns_q1_len3;
            4: parse_dns_q1_len4;
            5: parse_dns_q1_len5;
            6: parse_dns_q1_len6;
            7: parse_dns_q1_len7;
            0x8 &&& 0x8: parse_dns_q1_gr7; // from 8 to 15
            0x10 &&& 0x10: parse_dns_q1_gr7; // from 16 to 31
            0x20 &&& 0x20: parse_dns_q1_gr7; // from 32 to 63
            default: accept;
        }
    }
    state parse_dns_q1_len1 {
        pkt.extract(p.q1_part1);
        parse_limit.decrement(8w01);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len2 {
        pkt.extract(p.q1_part2);
        parse_limit.decrement(8w02);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len3 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        parse_limit.decrement(8w03);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len4 {
        pkt.extract(p.q1_part4);
        parse_limit.decrement(8w04);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len5 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        parse_limit.decrement(8w05);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len6 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        parse_limit.decrement(8w06);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len7 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        parse_limit.decrement(8w07);
        transition parse_dns_query2;
    }
    state parse_dns_q1_gr7 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        ig_md.partial_parsing = 1; // partial label parsed
        // Check if this domain is a TLD
        transition select(p.label1.label_len) { 
            8: check_tld_q1_8;
            9: check_tld_q1_9;
            10: check_tld_q1_10;
            11: check_tld_q1_11;
            12: check_tld_q1_12;
            13: check_tld_q1_13;
            default: accept;
        }
    }

    state check_tld_q1_8 {
        // Lookup 2 characters: 1 character that we did not extract, and another for actual length of next subdomain (I already extracted 7 before)
        bit<16> label2_len = pkt.lookahead<bit<16>>();
        transition select (label2_len[15:8]) {
            0: q1_is_tld;
            default: accept;
        }
    }
    state check_tld_q1_9 {
        // Lookup 3 characters: 2 characters that we did not extract, and another for actual length of next subdomain (I already extracted 7 before)
        bit<24> label2_len = pkt.lookahead<bit<24>>();
        transition select (label2_len[23:16]) {
            0: q1_is_tld;
            default: accept;
        }
    }
    state check_tld_q1_10 {
        // Lookup 4 characters: 3 characters that we did not extract, and another for actual length of next subdomain (I already extracted 7 before)
        bit<32> label2_len = pkt.lookahead<bit<32>>();
        transition select (label2_len[31:24]) {
            0: q1_is_tld;
            default: accept;
        }
    }
    state check_tld_q1_11 {
        // Lookup 5 characters: 4 characters that we did not extract, and another for actual length of next subdomain (I already extracted 7 before)
        bit<40> label2_len = pkt.lookahead<bit<40>>();
        transition select (label2_len[39:32]) {
            0: q1_is_tld;
            default: accept;
        }
    }
    state check_tld_q1_12 {
        // Lookup 6 characters: 5 characters that we did not extract, and another for actual length of next subdomain (I already extracted 7 before)
        bit<48> label2_len = pkt.lookahead<bit<48>>();
        transition select (label2_len[47:40]) {
            0: q1_is_tld;
            default: accept;
        }
    }
    state check_tld_q1_13 {
        // Lookup 7 characters: 6 characters that we did not extract, and another for actual length of next subdomain (I already extracted 7 before)
        bit<56> label2_len = pkt.lookahead<bit<56>>();
        transition select (label2_len[55:48]) {
            0: q1_is_tld;
            default: accept;
        }
    }
    state q1_is_tld {
        ig_md.tld = 1;
        transition accept;
    }
    state q1_is_tld_done {
        pkt.extract(p.label2);
        ig_md.tld = 1;
        transition parse_query_tc;
    }
    
    // Parsel DNS Query Label 2
    state parse_dns_query2 {
        bit<8> label2_len = pkt.lookahead<bit<8>>();
        ig_md.next_label_len = label2_len;
        ig_md.recirculate_metadata.recirculate_bit = 0;
        transition select(label2_len) {
            0: q1_is_tld_done;
            1: preparse_dns_q2_len1_tld;
            2: preparse_dns_q2_len2_tld;
            3: preparse_dns_q2_len3_tld;
            4: preparse_dns_q2_len4_tld;
            5: preparse_dns_q2_len5_tld;
            6: preparse_dns_q2_len6_tld;
            7: preparse_dns_q2_len7_tld;
            8: preparse_dns_q2_len8_tld;
            9: preparse_dns_q2_len9_tld;
            10: preparse_dns_q2_len10_tld;
            11: preparse_dns_q2_len11_tld;
            0x8 &&& 0x8: parse_dns_q2_gr7; // from 8 to 15
            0x10 &&& 0x10: parse_dns_q2_gr7; // from 16 to 31
            0x20 &&& 0x20: parse_dns_q2_gr7; // from 32 to 63
            default: accept;
        }
    }
    
    state preparse_dns_q2_len1_tld {
        bit<24> label3_len = pkt.lookahead<bit<24>>();
        transition select (label3_len[23:16]) {
            0: accept;
            default: preparse_dns_q2_len1;
        }
    }
    state preparse_dns_q2_len1 {
        // parse_limit.decrement(8w01);
        parse_limit.decrement(8w02);
        transition select(parse_limit.is_negative()) {
            true: accept;
            false: parse_dns_q2_len1;
        }
    }
    state parse_dns_q2_len1 {
        pkt.extract(p.label2);
        pkt.extract(p.q2_part1);
        transition parse_dns_query3;
        // transition parse_dns_query3_tld;
    }

    state preparse_dns_q2_len2_tld {
        bit<32> label3_len = pkt.lookahead<bit<32>>();
        transition select (label3_len[31:24]) {
            0: accept;
            default: preparse_dns_q2_len2;
        }
    }
    state preparse_dns_q2_len2 {
        // parse_limit.decrement(8w02);
        parse_limit.decrement(8w03);
        transition select(parse_limit.is_negative()) {
            true: accept;
            false: parse_dns_q2_len2;
        }
    }
    state parse_dns_q2_len2 {
        pkt.extract(p.label2);
        pkt.extract(p.q2_part2);
        transition parse_dns_query3;
        // transition parse_dns_query3_tld;
    }
    
    // length of q2 is 3 (len unextracted) --> extract 1 + 3 + 1 = 5 bytes
    state q2_is_tld_len3 {
        ig_md.tld = 2;
        transition preparse_dns_q2_len3;
    }
    state preparse_dns_q2_len3_tld {
        bit<40> label3_len = pkt.lookahead<bit<40>>();
        transition select (label3_len[39:32]) {
            0: accept;
            default: preparse_dns_q2_len3;
        }
    }
    state preparse_dns_q2_len3 {
        // parse_limit.decrement(8w03);
        parse_limit.decrement(8w04);
        transition select(parse_limit.is_negative()) {
            true: accept;
            false: parse_dns_q2_len3;
        }
    }
    state parse_dns_q2_len3 {
        pkt.extract(p.label2);
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        transition select (is_recirc_char.is_negative()) {
            true: end_b4_q3;
            false: parse_dns_query3;
            // false: parse_dns_query3_tld;
        }
    }

    // length of q2 is 4 (len unextracted) --> extract 1 + 4 + 1 = 6 bytes
    state q2_is_tld_len4 {
        ig_md.tld = 2;
        transition preparse_dns_q2_len4;
    }
    state preparse_dns_q2_len4_tld {
        bit<48> label3_len = pkt.lookahead<bit<48>>();
        transition select (label3_len[47:40]) {
            // 0: q2_is_tld_len4;
            0: accept;
            default: preparse_dns_q2_len4;
        }
    }
    state preparse_dns_q2_len4 {
        // parse_limit.decrement(8w04);
        parse_limit.decrement(8w05);
        transition select(parse_limit.is_negative()) {
            true: parse_limit_inc4;
            false: parse_dns_q2_len4;
        }
    }
    state parse_limit_inc4 {
        // parse_limit.increment(8w04);
        parse_limit.increment(8w05);
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q2_len3;
    }
    state parse_dns_q2_len4 {
        pkt.extract(p.label2);
        pkt.extract(p.q2_part4);
        transition select (is_recirc_char.is_negative()) {
            true: end_b4_q3;
            false: parse_dns_query3;
            // false: parse_dns_query3_tld;
        }
    }

    // length of q2 is 5 (len unextracted) --> extract 1 + 5 + 1 = 7 bytes
    state q2_is_tld_len5 {
        ig_md.tld = 2;
        transition preparse_dns_q2_len5;
    }
    state preparse_dns_q2_len5_tld {
        bit<56> label3_len = pkt.lookahead<bit<56>>();
        transition select (label3_len[55:48]) {
            // 0: q2_is_tld_len5;
            0: accept;
            default: preparse_dns_q2_len5;
        }
    }
    state preparse_dns_q2_len5 {
        // parse_limit.decrement(8w05);
        parse_limit.decrement(8w06);
        transition select(parse_limit.is_negative()) {
            true: parse_limit_inc5;
            false: parse_dns_q2_len5;
        }
    }
    state parse_limit_inc5 {
        // parse_limit.increment(8w05);
        parse_limit.increment(8w06);
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q2_len4;
    }
    state parse_dns_q2_len5 {
        pkt.extract(p.label2);
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part4);
        transition select (is_recirc_char.is_negative()) {
            true: end_b4_q3;
            false: parse_dns_query3;
            // false: parse_dns_query3_tld;
        }
    }

    // length of q2 is 6 (len unextracted) --> extract 1 + 6 + 1 = 8 bytes
    state q2_is_tld_len6 {
        ig_md.tld = 2;
        transition preparse_dns_q2_len6;
    }
    state preparse_dns_q2_len6_tld {
        bit<64> label3_len = pkt.lookahead<bit<64>>();
        transition select (label3_len[63:56]) {
            // 0: q2_is_tld_len6;
            0: accept;
            default: preparse_dns_q2_len6;
        }
    }
    state preparse_dns_q2_len6 {
        // parse_limit.decrement(8w06);
        parse_limit.decrement(8w07);
        transition select(parse_limit.is_negative()) {
            true: parse_limit_inc6;
            false: parse_dns_q2_len6;
        }
    }
    state parse_limit_inc6 {
        // parse_limit.increment(8w06);
        parse_limit.increment(8w07);
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q2_len5;
    }
    state parse_dns_q2_len6 {
        pkt.extract(p.label2);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        transition select (is_recirc_char.is_negative()) {
            true: end_b4_q3;
            false: parse_dns_query3;
            // false: parse_dns_query3_tld;
        }
    }

    // length of q2 is 7 (len unextracted) --> extract 1 + 7 + 1 = 9 bytes
    state q2_is_tld_len7 {
        ig_md.tld = 2;
        transition preparse_dns_q2_len7;
    }
    // length of q2 is 7 (len unextracted) --> extract 1 + 7 + 1 = 9 bytes
    state preparse_dns_q2_len7_tld {
        bit<72> label3_len = pkt.lookahead<bit<72>>();
        transition select (label3_len[71:64]) {
            // 0: q2_is_tld_len7;
            0: accept;
            default: preparse_dns_q2_len7;
        }
    }
    state preparse_dns_q2_len7 {
        // parse_limit.decrement(8w07);
        parse_limit.decrement(8w08);
        transition select(parse_limit.is_negative()) {
            true: parse_limit_inc7;
            false: parse_dns_q2_len7;
        }
    }
    state parse_limit_inc7 {
        // parse_limit.increment(8w07);
        parse_limit.increment(8w08);
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q2_len6;
    }
    state parse_dns_q2_len7 {
        pkt.extract(p.label2);
        pkt.extract(p.q2_part1);
        pkt.extract(p.q2_part2);
        pkt.extract(p.q2_part4);
        transition select (is_recirc_char.is_negative()) {
            true: end_b4_q3;
            false: parse_dns_query3;
            // false: parse_dns_query3_tld;
        }
    }
    
    state q2_is_tld_gr7 {
        ig_md.tld = 2;
        transition parse_dns_q2_gr7;
    }
    // length of q2 is 8 (len unextracted) --> extract 1 + 8 + 1 = 10 bytes
    state preparse_dns_q2_len8_tld {
        bit<80> label3_len = pkt.lookahead<bit<80>>();
        transition select (label3_len[79:72]) {
            // 0: q2_is_tld_gr7;
            0: accept;
            default: parse_dns_q2_gr7;
        }
    }
    // length of q2 is 9 (len unextracted) --> extract 1 + 9 + 1 = 11 bytes
    state preparse_dns_q2_len9_tld {
        bit<88> label3_len = pkt.lookahead<bit<88>>();
        transition select (label3_len[87:80]) {
            // 0: q2_is_tld_gr7;
            0: accept;
            default: parse_dns_q2_gr7;
        }
    }
    // length of q2 is 10 (len unextracted) --> extract 1 + 10 + 1 = 12 bytes
    state preparse_dns_q2_len10_tld {
        bit<96> label3_len = pkt.lookahead<bit<96>>();
        transition select (label3_len[95:88]) {
            // 0: q2_is_tld_gr7;
            0: accept;
            default: parse_dns_q2_gr7;
        }
    }
    // length of q2 is 11 (len unextracted) --> extract 1 + 11 + 1 = 13 bytes
    state preparse_dns_q2_len11_tld {
        bit<104> label3_len = pkt.lookahead<bit<104>>();
        transition select (label3_len[103:96]) {
            // 0: q2_is_tld_gr7;
            0: accept;
            default: parse_dns_q2_gr7;
        }
    }

    state q2_is_tld_done {
        pkt.extract(p.label3);
        ig_md.tld = 2;
        transition parse_query_tc;
    }


    state parse_dns_q2_gr7 {
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q2_len7;
    }

    // Parsel DNS Query Label 3
    // ?? todo: add a state: preparse_dns_query3
    state end_b4_q3 {
        ig_md.parsed_labels_len = MAX_CHARS;
        transition accept;
    }
    
    state parse_dns_query3 {
        bit<8> label3_len = pkt.lookahead<bit<8>>();
        ig_md.next_label_len = label3_len;

        transition select(label3_len) {
            // 0: parse_query_tc;
            0: q2_is_tld_done; // most probably will not enter this
            1: preparse_dns_q3_len1_tld;
            2: preparse_dns_q3_len2_tld;
            3: preparse_dns_q3_len3_tld;
            4: preparse_dns_q3_len4_tld;
            5: preparse_dns_q3_len5_tld;
            6: preparse_dns_q3_len6_tld;
            7: preparse_dns_q3_len7_tld;
            8: preparse_dns_q3_len8_tld;
            9: preparse_dns_q3_len9_tld;
            10: preparse_dns_q3_len10_tld;
            11: preparse_dns_q3_len11_tld;
            0x8 &&& 0x8: parse_dns_q3_gr7; // from 8 to 15
            0x10 &&& 0x10: parse_dns_q3_gr7; // from 16 to 31
            0x20 &&& 0x20: parse_dns_q3_gr7; // from 32 to 63
            default: accept;
        }
    }

    state preparse_dns_q3_len1_tld {
        bit<24> label4_len = pkt.lookahead<bit<24>>();
        transition select (label4_len[23:16]) {
            0: accept;
            default: preparse_dns_q3_len1;
        }
    }
    state preparse_dns_q3_len1 {
        // parse_limit.decrement(8w01);
        parse_limit.decrement(8w02);
        transition select(parse_limit.is_negative()) {
            true: accept;
            false: parse_dns_q3_len1;
        }
    }
    state parse_dns_q3_len1 {
        pkt.extract(p.label3);
        pkt.extract(p.q3_part1);
        transition parse_dns_query_last;
    }
    

    state preparse_dns_q3_len2_tld {
        bit<32> label4_len = pkt.lookahead<bit<32>>();
        transition select (label4_len[31:24]) {
            0: accept;
            default: preparse_dns_q3_len2;
        }
    }
    state preparse_dns_q3_len2 {
        // parse_limit.decrement(8w02);
        parse_limit.decrement(8w03);
        transition select(parse_limit.is_negative()) {
            true: accept;
            false: parse_dns_q3_len2;
        }
    }
    state parse_dns_q3_len2 {
        pkt.extract(p.label3);
        pkt.extract(p.q3_part2);
        transition parse_dns_query_last;
    }
    
    // length of q3 is 3 (len unextracted) --> extract 1 + 3 + 1 = 5 bytes
    state q3_is_tld_len3 {
        ig_md.tld = 3;
        transition preparse_dns_q3_len3;
    }
    state preparse_dns_q3_len3_tld {
        bit<40> label4_len = pkt.lookahead<bit<40>>();
        transition select (label4_len[39:32]) {
            // 0: q3_is_tld_len3;
            0: accept;
            default: preparse_dns_q3_len3;
        }
    }
    state preparse_dns_q3_len3 {
        // parse_limit.decrement(8w03);
        parse_limit.decrement(8w04);
        transition select(parse_limit.is_negative()) {
            true: accept;
            false: parse_dns_q3_len3;
        }
    }
    // state parse_limit_inc3_2 {
    //     // parse_limit.increment(8w03);
    //     parse_limit.increment(8w04);
    //     ig_md.recirculate_metadata.recirculate_bit = 0;
    //     ig_md.partial_parsing = 0; // no partial label parsed
    //     is_recirc_char.decrement(8w01);
    //     transition accept;
    // }
    state parse_dns_q3_len3 {
        pkt.extract(p.label3);
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        transition select (is_recirc_char.is_negative()) {
            true: accept;
            false: parse_dns_query_last;
        }
    }

    // length of q3 is 4 (len unextracted) --> extract 1 + 4 + 1 = 6 bytes
    state q3_is_tld_len4 {
        ig_md.tld = 3;
        transition preparse_dns_q3_len4;
    }
    state preparse_dns_q3_len4_tld {
        bit<48> label4_len = pkt.lookahead<bit<48>>();
        transition select (label4_len[47:40]) {
            // 0: q3_is_tld_len4;
            0: accept;
            default: preparse_dns_q3_len4;
        }
    }
    state preparse_dns_q3_len4 {
        // parse_limit.decrement(8w04);
        parse_limit.decrement(8w05);
        transition select(parse_limit.is_negative()) {
            true: parse_limit_inc4_2;
            false: parse_dns_q3_len4;
        }
    }
    state parse_limit_inc4_2 {
        // parse_limit.increment(8w04);
        parse_limit.increment(8w05);
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q3_len3;
    }
    state parse_dns_q3_len4 {
        pkt.extract(p.label3);
        pkt.extract(p.q3_part4);
        transition select (is_recirc_char.is_negative()) {
            true: accept;
            false: parse_dns_query_last;
        }
    }

    // length of q3 is 5 (len unextracted) --> extract 1 + 5 + 1 = 7 bytes
    state q3_is_tld_len5 {
        ig_md.tld = 3;
        transition preparse_dns_q3_len5;
    }
    state preparse_dns_q3_len5_tld {
        bit<56> label4_len = pkt.lookahead<bit<56>>();
        transition select (label4_len[55:48]) {
            // 0: q3_is_tld_len5;
            0: accept;
            default: preparse_dns_q3_len5;
        }
    }
    state preparse_dns_q3_len5 {
        // parse_limit.decrement(8w05);
        parse_limit.decrement(8w06);
        transition select(parse_limit.is_negative()) {
            true: parse_limit_inc5_2;
            false: parse_dns_q3_len5;
        }
    }
    state parse_limit_inc5_2 {
        // parse_limit.increment(8w05);
        parse_limit.increment(8w06);
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q3_len4;
    }
    state parse_dns_q3_len5 {
        pkt.extract(p.label3);
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part4);
        transition select (is_recirc_char.is_negative()) {
            true: accept;
            false: parse_dns_query_last;
        }
    }

    // length of q3 is 6 (len unextracted) --> extract 1 + 6 + 1 = 8 bytes
    state q3_is_tld_len6 {
        ig_md.tld = 3;
        transition preparse_dns_q3_len6;
    }
    state preparse_dns_q3_len6_tld {
        bit<64> label4_len = pkt.lookahead<bit<64>>();
        transition select (label4_len[63:56]) {
            // 0: q3_is_tld_len6;
            0: accept;
            default: preparse_dns_q3_len6;
        }
    }
    state preparse_dns_q3_len6 {
        // parse_limit.decrement(8w06);
        parse_limit.decrement(8w07);
        transition select(parse_limit.is_negative()) {
            true: parse_limit_inc6_2;
            false: parse_dns_q3_len6;
        }
    }
    state parse_limit_inc6_2 {
        // parse_limit.increment(8w06);
        parse_limit.increment(8w07);
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q3_len5;
    }
    state parse_dns_q3_len6 {
        pkt.extract(p.label3);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        transition select (is_recirc_char.is_negative()) {
            true: accept;
            false: parse_dns_query_last;
        }
    }

    // length of q3 is 7 (len unextracted) --> extract 1 + 7 + 1 = 9 bytes
    state q3_is_tld_len7 {
        ig_md.tld = 3;
        transition preparse_dns_q3_len7;
    }
    state preparse_dns_q3_len7_tld {
        bit<72> label4_len = pkt.lookahead<bit<72>>();
        transition select (label4_len[71:64]) {
            // 0: q3_is_tld_len7;
            0: accept;
            default: preparse_dns_q3_len7;
        }
    }
    state preparse_dns_q3_len7 {
        // parse_limit.decrement(8w07);
        parse_limit.decrement(8w08);
        transition select(parse_limit.is_negative()) {
            true: parse_limit_inc7_2;
            false: parse_dns_q3_len7;
        }
    }
    state parse_limit_inc7_2 {
        // parse_limit.increment(8w07);
        parse_limit.increment(8w08);
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q3_len6;
    }
    state parse_dns_q3_len7 {
        pkt.extract(p.label3);
        pkt.extract(p.q3_part1);
        pkt.extract(p.q3_part2);
        pkt.extract(p.q3_part4);
        transition select (is_recirc_char.is_negative()) {
            true: accept;
            false: parse_dns_query_last;
        }
    }
    
    state q3_is_tld_gr7 {
        ig_md.tld = 3;
        transition parse_dns_q3_gr7;
    }
    // length of q3 is 8 (len unextracted) --> extract 1 + 8 + 1 = 10 bytes
    state preparse_dns_q3_len8_tld {
        bit<80> label4_len = pkt.lookahead<bit<80>>();
        transition select (label4_len[79:72]) {
            // 0: q3_is_tld_gr7;
            0: accept;
            default: parse_dns_q3_gr7;
        }
    }
    // length of q3 is 9 (len unextracted) --> extract 1 + 9 + 1 = 11 bytes
    state preparse_dns_q3_len9_tld {
        bit<88> label4_len = pkt.lookahead<bit<88>>();
        transition select (label4_len[87:80]) {
            // 0: q3_is_tld_gr7;
            0: accept;
            default: parse_dns_q3_gr7;
        }
    }
    // length of q3 is 10 (len unextracted) --> extract 1 + 10 + 1 = 12 bytes
    state preparse_dns_q3_len10_tld {
        bit<96> label4_len = pkt.lookahead<bit<96>>();
        transition select (label4_len[95:88]) {
            // 0: q3_is_tld_gr7;
            0: accept;
            default: parse_dns_q3_gr7;
        }
    }
    // length of q3 is 11 (len unextracted) --> extract 1 + 11 + 1 = 13 bytes
    state preparse_dns_q3_len11_tld {
        bit<104> label4_len = pkt.lookahead<bit<104>>();
        transition select (label4_len[103:96]) {
            // 0: q3_is_tld_gr7;
            0: accept;
            default: parse_dns_q3_gr7;
        }
    }
    state parse_dns_q3_gr7 {
        ig_md.partial_parsing = 1; // partial label parsed
        is_recirc_char.decrement(8w01);
        transition preparse_dns_q3_len7;
    }
    state q3_is_tld_done {
        pkt.extract(p.label3);
        ig_md.tld = 3;
        transition parse_query_tc;
    }

    // Parsel DNS Query Additional label
    state parse_dns_query_last {
        pkt.extract(p.label_last);

        transition select(p.label_last.label_len) {
            0: q3_is_tld_done;
            default: accept;
        }
    }
    state parse_query_tc {
        pkt.extract(p.query_tc);
        ig_md.parsed_answer = 0;
        ig_md.parsed_dns_query = 1;
        ig_md.next_label_len = 0;
        transition parse_dns_answer;
    }

    state parse_dns_answer {
        pkt.extract(p.dns_answer);
        transition select(p.dns_answer.tc_ans.type) {
            1: parse_a_ip;
            // 5: parse_cname_arbiter;
            default: accept;
        }
    }

    state parse_a_ip {
        pkt.extract(p.dns_ip);
        ig_md.parsed_answer = 1;

        transition accept;
    }
}
/**************************END OF PARSER**************************/


control calc_long_hash (in bit<LABEL_LENGTH_C> label, out bit<HASH_LENGTH_C> hash) (bit<16> coeff) {
    CRCPolynomial<bit<16>>(coeff = coeff, reversed = false, msb = false, extended = false,  
    init = 0xFFFF, xor = 0xFFFF ) poly;
    Hash<bit<HASH_LENGTH_C>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        hash = hash_algo.get({label});
    }
    apply{
        do_hash();
    }
}

control calc_concat_hash (inout bit<HASH_LENGTH_C> hash_concat_hashes, in bit<16> full_label_1_hash) (bit<16> coeff) {
    CRCPolynomial<bit<16>>(coeff = coeff, reversed = false, msb = false, extended = false,  
    init = 0xFFFF, xor = 0xFFFF ) poly;
    Hash<bit<HASH_LENGTH_C>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        bit<16> zeros_hex = 0x0000;
        hash_concat_hashes = hash_algo.get({hash_concat_hashes, full_label_1_hash});
    }
    apply{
        do_hash();
    }
}
control calc_concat_hash168 (inout bit<HASH_LENGTH_C> hash_concat_hashes, in bit<168> full_labels) (bit<16> coeff) {
    CRCPolynomial<bit<16>>(coeff = coeff, reversed = false, msb = false, extended = false,  
    init = 0xFFFF, xor = 0xFFFF ) poly;
    Hash<bit<HASH_LENGTH_C>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        bit<16> zeros_hex = 0x0000;
        hash_concat_hashes = hash_algo.get({hash_concat_hashes, full_labels});
    }
    apply{
        do_hash();
    }
}


// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------
control SwitchIngress(inout Parsed_packet headers,
                inout ig_metadata_t ig_md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
    // Last two hashes
    calc_concat_hash(coeff=0x1021) H_last_label;

    // Define the hashes for the label
    calc_long_hash(coeff=0x1021) hash_label_1;
    calc_long_hash(coeff=0x1021) hash_label_2;
    calc_long_hash(coeff=0x1021) hash_label_3;
    // labels 1, 2, 3
    bit<LABEL_LENGTH_C> full_label_1; 
    bit<HASH_LENGTH_C> full_label_1_hash;  
    bit<LABEL_LENGTH_C> full_label_2; 
    bit<HASH_LENGTH_C> full_label_2_hash;  
    bit<LABEL_LENGTH_C> full_label_3; 
    bit<HASH_LENGTH_C> full_label_3_hash;
    bit<168> full_labels; 
    bit<HASH_LENGTH_C> hash_concat_hashes; // init (for recirculation purposes) 
    bit<HASH_LENGTH_C> hash_last_label;

    
    action send(PortId_t port){
        ig_intr_tm_md.ucast_egress_port = port;
    }
    action drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }

    action recirculation(PortId_t port){
        ig_intr_tm_md.ucast_egress_port = port;
    }

    // For basic destination IP forwarding
    table ipv4_host {
        key = {
            headers.ipv4.dst: exact;
        }
        actions = {
            send;
            NoAction;
        }
        size = 100;
        default_action = NoAction();
    }
   

    // RF Data plane tables
    action nop() {
    }
    action SetClass0(bit<8> classe) {
        ig_md.class0 = classe;
    }
    action SetClass1(bit<8> classe) {
        ig_md.class1 = classe;
    }
    action SetClass2(bit<8> classe) {
        ig_md.class2 = classe;
    }
    action set_final_class() {

    }
    action SetCode0(bit<32> code0, bit<32> code1) {
        ig_md.code0 = code0;
        ig_md.code1 = code1;
    }
    action SetCode1(bit<32> code0, bit<32> code1) {
        ig_md.code0 = code0;
        ig_md.code1 = code1;
    }
    action SetCode2(bit<32> code0, bit<32> code1) {
        ig_md.code0 = code0;
        ig_md.code1 = code1;
    }
    action SetCode3(bit<32> code0, bit<32> code1) {
        ig_md.code0 = code0;
        ig_md.code1 = code1;
    }
    
    action set_class1(bit<8> class1) {
        ig_md.class1 = class1;
    }
    table table_feature0 {
        key = {ig_md.feature0: ternary;}
        actions = {@defaultonly nop; SetCode0;}
        size = 100;
        const default_action = nop();
    }
    table table_feature1 {
        key = {ig_md.feature1: ternary;}
        actions = {@defaultonly nop; SetCode1;}
        size = 100;
        const default_action = nop();
    }
    table table_feature2 {
        key = {ig_md.feature2: ternary;}
        actions = {@defaultonly nop; SetCode2;}
        size = 100;
        const default_action = nop();
    }  
    table table_feature3 {
        key = {ig_md.feature3: ternary;}
        actions = {@defaultonly nop; SetCode3;}
        size = 100;
        const default_action = nop();
    } 

    table code_table0 {
        key = {ig_md.code0: ternary;}
        actions = {@defaultonly nop; SetClass0;}
        const default_action = nop();
    }
    table code_table1 {
        key = {ig_md.code1: ternary;}
        actions = {@defaultonly nop; SetClass1;}
        const default_action = nop();
    }
    table code_table2 {
        key = {ig_md.code2: ternary;}
        actions = {@defaultonly nop; SetClass2;}
        const default_action = nop();
    }

    table voting_table {
        key = {
            ig_md.class0: exact;
            ig_md.class1: exact;
            // ig_md.class2: exact;
        }
        actions = {@defaultonly nop; set_final_class;}
        const default_action = nop();
    }


    apply {
        // Regular IP packet
        ipv4_host.apply();

        // NXD parsing is done
        if (headers.recirculate.isValid() && headers.recirculate.recirculate_bit == DONE_PARSING) {
            table_feature0.apply();
            table_feature1.apply();
            table_feature2.apply();
            table_feature3.apply();

            code_table0.apply();
            code_table1.apply();
            // code_table2.apply();

            // voting table
            ig_intr_dprsr_md.digest_type = 1;
            if (voting_table.apply().hit) {
                ig_intr_dprsr_md.digest_type = 1;
            } 

            headers.recirculate.setInvalid();
            ig_intr_tm_md.ucast_egress_port = 1;
            // drop();
            
        }

        else if (ig_md.is_dns == 1 && headers.dns_header.resp_code == NXDomain)  {

            // if this is a recirculated packet, set the hash_concat_hashes, and set the recirculate bit 
            if (! headers.recirculate.isValid())  {
                headers.recirculate.setValid();
                headers.recirculate.dga_ip = headers.ipv4.dst;
                headers.recirculate.recirculate_id = RECIRCULATE_ID_C;
                headers.recirculate.hash_concat_hashes = 0x0000;
                headers.recirculate.bigram = 0x00000000;
                // hash_concat_hashes = 0x0000;
                // hash_last_label = 0x0000;
                headers.ethernet.src = ig_intr_md.ingress_mac_tstamp;
            }
            
            // figure out the next N characters to be parsed in the next recirculation label_header: next_label_len
            // figure out the number of characters parsed so far: headers.label1.label_len

            if(ig_md.partial_parsing == 1) {
                headers.recirculate.recirculate_bit = PARTIAL_LABEL_PARSING;

                // only label one is parsed
                if (headers.label1.isValid() && headers.label1.label_len != 0 && ! headers.label2.isValid()){
                    ig_md.next_label_len = headers.label1.label_len - MAX_CHARS;

                    // number of subdomains
                   //  headers.recirculate.num_subdomains = headers.recirculate.num_subdomains + 1;
                }
                // more than one label one is parsed (2 and above)
                else {
                    //
                    //    Partial parsing from:
                    //        label2 --> next_label_len(remaining from label2) = label2_len  - MAX_CHARS  + label1_len + 1
                    //        label3 --> next_label_len(remaining from label3) = label3_len  - MAX_CHARS  + label1_len + 1 + label2_len + 1
                    //
                    ig_md.next_label_len = ig_md.next_label_len + headers.label1.label_len;

                    // 2 labels valid
                    if (headers.label1.isValid() && headers.label2.isValid() && headers.label2.label_len != 0 && ! headers.label3.isValid()) {
                        ig_md.next_label_len = ig_md.next_label_len + 1;

                        // number of subdomains
                        headers.recirculate.num_subdomains = headers.recirculate.num_subdomains + 1;
                    }
                    

                    // 3 labels valid
                    if (headers.label1.isValid() && headers.label2.isValid() && headers.label3.isValid() && headers.label3.label_len != 0) {
                        ig_md.next_label_len = ig_md.next_label_len + headers.label2.label_len;
                        ig_md.next_label_len = ig_md.next_label_len + 2;

                        // number of subdomains
                        headers.recirculate.num_subdomains = headers.recirculate.num_subdomains + 2;
                    }
                    ig_md.next_label_len = ig_md.next_label_len - MAX_CHARS;
                }

                headers.label1.label_len = MAX_CHARS;
                headers.recirculate.domain_name_length =  headers.recirculate.domain_name_length + MAX_CHARS;
                headers.recirculate.next_label_len =  ig_md.next_label_len;
            }
            // full label parsing: could be due to reaching MAX_CHARS, or due to next label is not worth parsing (I can parse from the next label 1 or 2 chars at MAX)
            else {

                headers.recirculate.recirculate_bit = FULL_LABEL_PARSING;

                if (headers.label1.isValid() && headers.label1.label_len != 0){

                    // domain name length 
                    headers.recirculate.domain_name_length = headers.recirculate.domain_name_length + headers.label1.label_len;

                    // number of subdomains
                    headers.recirculate.num_subdomains = headers.recirculate.num_subdomains + 1;
                }
                
                if (headers.label2.isValid() && headers.label2.label_len != 0){
                    headers.label1.label_len = headers.label1.label_len + headers.label2.label_len;
                    headers.label1.label_len = headers.label1.label_len + 1;

                    // domain name length 
                    headers.recirculate.domain_name_length =  headers.recirculate.domain_name_length + headers.label2.label_len;
                    headers.recirculate.domain_name_length =  headers.recirculate.domain_name_length + 1;

                    // number of subdomains
                    headers.recirculate.num_subdomains = headers.recirculate.num_subdomains + 1;
                }

                if (headers.label3.isValid() && headers.label3.label_len != 0){
                    headers.label1.label_len = headers.label1.label_len + headers.label3.label_len;
                    headers.label1.label_len = headers.label1.label_len + 1;
                    
                    // domain name length 
                    headers.recirculate.domain_name_length =  headers.recirculate.domain_name_length + headers.label3.label_len;
                    headers.recirculate.domain_name_length =  headers.recirculate.domain_name_length + 1;

                    // number of subdomains
                    headers.recirculate.num_subdomains = headers.recirculate.num_subdomains + 1;
                }
            }
        
            
            // TLD handling 
            if (headers.label1.isValid() && ig_md.tld == 1) {
                if (headers.q1_part1.isValid()){
                    full_label_1[7:0] = headers.q1_part1.part;
                }
                if (headers.q1_part2.isValid()){
                    full_label_1[23:8] = headers.q1_part2.part;
                }
                if (headers.q1_part4.isValid()){
                    full_label_1[55:24] = headers.q1_part4.part;
                }
                // full_labels[55:0] = full_label_1;
                hash_label_1.apply(full_label_1, full_label_1_hash);
                
                // TLD
                H_last_label.apply(headers.recirculate.hash_last_label, full_label_1_hash);

                // if (ig_md.tld == 1){
                //     H_last_label.apply(headers.recirculate.hash_last_label, full_label_1_hash);
                // }
            }
            
            // 2 labels valid
            /*
            else if (headers.label2.isValid() && ig_md.tld == 2){
                if (headers.q2_part1.isValid()){
                    full_label_2[7:0] = headers.q2_part1.part;
                }
                if (headers.q2_part2.isValid()){
                    full_label_2[23:8] = headers.q2_part2.part;
                }
                if (headers.q2_part4.isValid()){
                    full_label_2[55:24] = headers.q2_part4.part;
                }
                full_labels[111:56] = full_label_2;
                // hash_label_2.apply(full_label_2, full_label_2_hash);

                // TLD
                H_last_label.apply(headers.recirculate.hash_last_label, full_label_2_hash);
            }
            // 3 labels valid
            else if (headers.label3.isValid() && ig_md.tld == 3){
                if (headers.q3_part1.isValid()){
                    full_label_3[7:0] = headers.q3_part1.part;
                }
                if (headers.q3_part2.isValid()){
                    full_label_3[23:8] = headers.q3_part2.part;
                }
                if (headers.q3_part4.isValid()){
                    full_label_3[55:24] = headers.q3_part4.part;
                }
                full_labels[167:112] = full_label_3;
                // hash_label_3.apply(full_label_3, full_label_3_hash);
                
                // TLD
                H_last_label.apply(headers.recirculate.hash_last_label, full_label_3_hash);
            } 
            */

            // Parsed the whole domain name
            if (ig_md.parsed_dns_query == 1) {
                headers.recirculate.recirculate_bit = DONE_PARSING;
            }

            recirculation(68);

            // replace label2 and label3 length with "." in ASCII, which is 0x2E
            headers.label2.label_len = 0x2E;
            headers.label3.label_len = 0x2E;

        }

    }
    
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout Parsed_packet headers,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
         
    Digest<digest_t>() digest;

    apply {
        // For sending the features to the control plane
        if (ig_intr_dprsr_md.digest_type == 1) {
            digest.pack({headers.recirculate.dga_ip,
                        headers.recirculate.ip_reqs, 
                        headers.recirculate.dns_reqs,
                        headers.recirculate.bigram, 
                        headers.recirculate.domain_name_length,
                        headers.recirculate.num_subdomains, 
                        headers.recirculate.hash_last_label
                        });
        }
        pkt.emit(headers);

    }
}


// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out Parsed_packet p,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md
        ) {


    state start {
        pkt.extract(eg_intr_md);

        transition check_recirculate;
    }

    state check_recirculate {
        // parse recirculated packet here
        bit<8> recirculate_id = pkt.lookahead<bit<8>>();
        transition select(recirculate_id){
            RECIRCULATE_ID_C: parse_recirculate; // Hoping that the first 8 bits of MAC destination address is not 220
            _: parse_ethernet;
        }
    }
    state parse_recirculate {
        pkt.extract(eg_md.recirculate_metadata);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(p.ethernet);
        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }
	state parse_ip {
        pkt.extract(p.ipv4);
        eg_md.is_ip = 1;
        eg_md.is_dns = 0;
		transition select(p.ipv4.proto) {
			17: parse_udp;
			default: accept;
		}
	}
    state parse_udp {
        pkt.extract(p.udp);
		transition select(p.udp.dport, p.udp.sport) {
            (53,_): parse_dns_header;
            (_, 53): parse_dns_header;
			default: accept;
		}
	}
    state parse_dns_header {
        pkt.extract(p.dns_header);
		transition select(p.dns_header.is_response) {
            0: is_request_state;
            1: is_reponse_state;
			default: accept;
		}
	}
    state is_request_state {
        // eg_md.is_response = 0;
        eg_md.is_dns = 1; // request
        transition accept;
    }
    state is_reponse_state {
        // eg_md.is_response = 1;
        eg_md.is_dns = 2; // response
        transition parse_dns_query1;
    }
    // Parsel DNS Query Label 1
    state parse_dns_query1 {
        pkt.extract(p.label1);
        transition select(p.label1.label_len) {
            // ? what happens when 0
            0: accept;
            1: parse_dns_q1_len1;
            2: parse_dns_q1_len2;
            3: parse_dns_q1_len3;
            4: parse_dns_q1_len4;
            5: parse_dns_q1_len5;
            6: parse_dns_q1_len6;
            7: parse_dns_q1_len7;
            8: parse_dns_q1_len8;
            9: parse_dns_q1_len9;
            // 10: parse_dns_q1_len10;
            // 11: parse_dns_q1_len11;
            // 12: parse_dns_q1_len12;
            default: accept;
        }
    }

    state parse_dns_q1_len1 {
        pkt.extract(p.q1_part1);
        transition accept;
    }
    state parse_dns_q1_len2 {
        pkt.extract(p.q1_part2);
        transition accept;
    }
    state parse_dns_q1_len3 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        transition accept;
    }
    state parse_dns_q1_len4 {
        pkt.extract(p.q1_part4);
        transition accept;
    }
    state parse_dns_q1_len5 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        transition accept;
    }
    state parse_dns_q1_len6 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition accept;
    }
    state parse_dns_q1_len7 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition accept;
    }
    state parse_dns_q1_len8 {
        pkt.extract(p.q1_part8);
        transition accept;
    }
    // If we parse up to three labels, the maximum number of characters is limited to 9
    state parse_dns_q1_len9 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part8);
        transition accept;
    }

}


// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout Parsed_packet headers,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    bit<1> is_first;
    calc_long_hash(coeff=0x1021) hash_dns;
    calc_long_hash(coeff=0x1021) hash_ip;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) is_first_IP_hash;

    bit<16> index;

    action map_ngram_hdr(BigramVal bigram_val){
        eg_md.recirculate_metadata.bigram = eg_md.recirculate_metadata.bigram + bigram_val;
    }
    table static_bigram_p2 {
        key = {
            headers.q1_part2.isValid(): exact;
            headers.q1_part2.part: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p4_1 {
        key = {
            headers.q1_part4.isValid(): exact;
            headers.q1_part4.part[31:16]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p4_2 {
        key = {
            headers.q1_part4.isValid(): exact;
            headers.q1_part4.part[23:8]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p4_3 {
        key = {
            headers.q1_part4.isValid(): exact;
            headers.q1_part4.part[15:0]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p1p2 {
        key = {
            headers.q1_part1.isValid(): exact;
            headers.q1_part2.isValid(): exact;
            
            headers.q1_part1.part: exact;
            headers.q1_part2.part[15:8]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p1p4 {
        key = {
            headers.q1_part1.isValid(): exact;
            headers.q1_part4.isValid(): exact;

            headers.q1_part1.part: exact;
            headers.q1_part4.part[31:24]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p2p4 {
        key = {
            headers.q1_part2.isValid(): exact;
            headers.q1_part4.isValid(): exact;

            headers.q1_part2.part: exact;
            headers.q1_part4.part[31:24]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }

    table static_bigram_p8_1  {
        key = {
            headers.q1_part8.isValid(): exact;
            headers.q1_part8.part[15:0]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p8_2  {
        key = {
            headers.q1_part8.isValid(): exact;
            headers.q1_part8.part[23:8]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p8_3  {
        key = {
            headers.q1_part8.isValid(): exact;
            headers.q1_part8.part[31:16]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p8_4  {
        key = {
            headers.q1_part8.isValid(): exact;
            headers.q1_part8.part[39:24]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p8_5  {
        key = {
            headers.q1_part8.isValid(): exact;
            headers.q1_part8.part[47:32]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigram_p8_6  {
        key = {
            headers.q1_part8.isValid(): exact;
            headers.q1_part8.part[55:40]: exact;
        }
        actions = {
            map_ngram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    
    // ************************************************************ DNS and IP register ************************************************************
    // ************************************************************      Start        ************************************************************

    // maybe here instead of putting "_" in the unique_ips, I should specify the size of the register (it should match the number of IP addresses stored)
    Register<bit<8>, _>(HOST_MONITOR) unique_ips;
    RegisterAction<bit<8>, _, bit<1>> (unique_ips) is_unique_ips = {
        void apply(inout bit<8> value, out bit<1> is_first) {
            if (value == 0){
                is_first = 1;
            } else {
                is_first = 0;
            }
            value = value + 1;
        }
    };

    Register<bit<32>, _>(HOST_MONITOR) dns_reqs;
    RegisterAction<bit<32>, _, bit<32>> (dns_reqs) get_dns_reqs = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            result = register_data;
        }
    };
    RegisterAction<bit<32>, _, void> (dns_reqs) update_dns_reqs = {
        void apply(inout bit<32> register_data) {

            register_data = register_data + 1;
        }
    };

    Register<bit<32>, _>(HOST_MONITOR) ip_reqs;
    RegisterAction<bit<32>, _, bit<32>> (ip_reqs) get_ip_reqs = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            result = register_data;
        }
    };
    RegisterAction<bit<32>, _, void> (ip_reqs) update_ips_reqs = {
        void apply(inout bit<32> register_data) {

            register_data = register_data + 1;
        }
    };


    // ************************************************************ NXD iarrival register ************************************************************
    // ************************************************************      Start        ************************************************************
    Register<bit<32>, _>(HOST_MONITOR) nxd_iarrival;
    // update time of iarrival of this packet (NXD)
    RegisterAction<bit<32>, _, void> (nxd_iarrival) update_nxd_iarrival = {
        void apply(inout bit<32> register_data) {
            
            // register_data = eg_md.iarrival; //lpf_output_2;
            register_data = (bit<32>)eg_intr_md_from_prsr.global_tstamp;
            
        }
    };
    RegisterAction<bit<32>, _, bit<32>> (nxd_iarrival) get_nxd_iarrival = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            result =  register_data;
        }
    };
    // ************************************************************ NXD iarrival register ************************************************************
    // ************************************************************      End        ************************************************************


    
    // ************************************************************  IP_domain_nxd, tmstamp register1, register2 ************************************************************
    // ************************************************************      End        ************************************************************

    bit<168> full_labels;
    bit<16> full_labels_hash;
    calc_concat_hash168(coeff=0x1021) H_full_labels;

    apply { 

        headers.ethernet.dst = eg_intr_md_from_prsr.global_tstamp;

        if (eg_md.recirculate_metadata.isValid()) {

            // /*
            bit<LABEL_LENGTH_C> ip56 = (bit<LABEL_LENGTH_C>) eg_md.recirculate_metadata.dga_ip;
            bit<16> ip56_hash;
            hash_ip.apply(ip56, ip56_hash);

            bit<LABEL_LENGTH_C> ip_domain_nxd1;
            bit<LABEL_LENGTH_C> ip_domain_nxd2;
            bit<16> ip_domain_nxd1_hash;
            bit<16> ip_domain_nxd2_hash;



            if (eg_md.recirculate_metadata.recirculate_bit == DONE_PARSING) {
                // Get Nb of NXDs, rnd NXDs, DNS reqs, IP reqs
                
                eg_md.recirculate_metadata.dns_reqs = get_dns_reqs.execute(ip56_hash);
                eg_md.recirculate_metadata.ip_reqs = get_ip_reqs.execute(ip56_hash);
                eg_md.recirculate_metadata.i_arrival = eg_md.recirculate_metadata.i_arrival - (bit<32>)eg_intr_md_from_prsr.global_tstamp;
                // update timestamp
                update_nxd_iarrival.execute(ip56_hash);
            }

            if (headers.label1.isValid() && headers.label1.label_len != 0) {

                // Hash domain
                full_labels[7:0] = headers.q1_part1.part;
                full_labels[23:8] = headers.q1_part2.part;
                full_labels[55:24] = headers.q1_part4.part;
                H_full_labels.apply(eg_md.recirculate_metadata.hash_concat_hashes, full_labels);

                if (headers.label1.label_len <= 7) {
                    static_bigram_p2.apply();
                    static_bigram_p4_1.apply();
                    static_bigram_p4_2.apply();
                    static_bigram_p4_3.apply();
                    static_bigram_p1p2.apply();
                    if (! headers.q1_part2.isValid()){
                        static_bigram_p1p4.apply();
                    }
                    else {
                        static_bigram_p2p4.apply();
                    }
                }
                // else if (headers.label1.label_len == 8) {
                //     static_bigram_p8_1.apply();
                //     static_bigram_p8_2.apply();
                //     static_bigram_p8_3.apply();
                // }
                             
                
                // set invalid headers
                headers.q1_part1.setInvalid();
                headers.q1_part2.setInvalid();
                headers.q1_part4.setInvalid();

                if (eg_md.recirculate_metadata.recirculate_bit == FULL_LABEL_PARSING) {
                    headers.label1.setInvalid();
                }
                else {
                    headers.label1.label_len = eg_md.recirculate_metadata.next_label_len;
                }
            }
            
        }
        // Non-DNS packets
        else if (eg_md.is_ip == 1 && eg_md.is_dns == 0) { // normal packets (will not be recirculated)
            index = is_first_IP_hash.get(headers.ipv4.src + headers.ipv4.dst);
            is_first = is_unique_ips.execute(index);

            if (is_first == 1){
                
                bit<LABEL_LENGTH_C> ip56 = (bit<LABEL_LENGTH_C>) headers.ipv4.src;
                bit<16> ip56_hash;
                hash_ip.apply(ip56, ip56_hash);

                // update_unique_IP_req.execute(ip56_hash);
                update_ips_reqs.execute(ip56_hash);
                // Resubmit packet to send a message digest
            }
        } 
        //DNS requests (obv no recircualtion if it is a request)
        else if (eg_md.is_dns == 1) {
            bit<LABEL_LENGTH_C> ip56 = (bit<LABEL_LENGTH_C>) headers.ipv4.src;
            bit<16> ip56_hash;
            hash_dns.apply(ip56, ip56_hash);
            // update_DNS_requests.execute(ip56_hash);
            update_dns_reqs.execute(ip56_hash);
            // Resubmit packet to send a message digest
        }
    }
   
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout Parsed_packet headers,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
         // I am dropping the packet before being sent to the host with the recirculated header, so basically this recirculated header is just for the switch to hold metadata infromation, the host won't be receiving bogus DNS pakcets 
        pkt.emit(eg_md.recirculate_metadata);
        pkt.emit(headers);
    }
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
        ) pipe;

Switch(pipe) main;
