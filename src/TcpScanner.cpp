//
// Created by Adam Láníček on 2019-04-14.
//

#include "TcpScanner.h"

TcpScanner::TcpScanner(vector<int>& ports) : Scanner(ports) {}

State TcpScanner::scan_port(int port) {
    State state = OPEN;

//    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
//    char datagram[DATAGRAM_SIZE];
//    // IP header
//    struct ip *iph = (struct ip *) datagram;
//    // TCP header definition
//    struct tcp *tcph = (struct tcp *) (datagram + sizeof(struct ip));
//    struct sockaddr_in sin;
//    struct pseudo_header psh;
//
//    sin.sin_family = AF_INET;
//    sin.sin_port = htons(port);
//    sin.sin_addr.s_addr = inet_addr("1.1.1.1");
//
//    memset(datagram,0,DATAGRAM_SIZE);
//
//    iph->ip_hl = 5;
//    iph->ip_v = 4;
//    iph->ip_tos = 0;
//    iph->ip_len = sizeof(struct ip) + sizeof(struct tcp);
//    iph->ip_len += sizeof(struct tcp);
    return state;

}



