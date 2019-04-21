//
// Created by Adam Láníček on 2019-04-14.
//

#ifndef IPK_SCAN_SCANNER_H
#define IPK_SCAN_SCANNER_H

#include <iostream>
#include <stdexcept>
#include <cstdlib>
#include <map>

#include <cstring>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <pcap.h>


#include <sys/mman.h>
#include <signal.h>

#include "Logger.h"
#include "Argparser.h"

#define TIMEOUT 2

enum State {OPEN,CLOSED,FILTERED,NOT_CHECKED};

using namespace std;

struct pseudoTcpHdr
{
    struct in_addr ip_src;
    struct in_addr ip_dst;
    u_char zeros;
    u_char protocol;
    u_short tcp_len;
    struct tcphdr real_tcp;
};

struct pseudoUdpHdr
{
    struct in_addr ip_src;
    struct in_addr ip_dst;
    u_char zeros;
    u_char protocol;
    u_short udp_len;
    struct udphdr real_udp;
};

class Scanner {
    public:
        Scanner(vector<int> &port_vector, ArgParser& args);
        void run_scan();
        virtual State scan_port(int port) = 0;
        void resolve_target_info();
        void print_header();
        void print_results(string protocol);
    private:
        //bool validate_ip(char *host);

    protected:
        ArgParser &args;
        void get_iface_name();
        map<State,string> state_map;
        map<int,State> results_map;
        vector<int>& ports;
        char host_name[20];
        char host_ip[20];

        struct addrinfo *candidates;
        struct addrinfo *target;

        struct ifaddrs *ifaddr;
        struct ifaddrs *ifa;

        void find_match_host_if_fam();
        unsigned short check_sum(unsigned short *buf, int n_words);
        in_port_t get_in_port(struct sockaddr *sa);
};


#endif //IPK_SCAN_SCANNER_H
