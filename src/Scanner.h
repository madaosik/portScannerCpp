//
// Created by Adam Láníček on 2019-04-14.
//

#ifndef IPK_SCAN_SCANNER_H
#define IPK_SCAN_SCANNER_H

#include <vector>
#include <map>
#include <string>

#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "Logger.h"

#define MAX_LEN 50
#define DATAGRAM_SIZE 8192
#define SRC_PORT 21
#define SRC_IP "192.168.10.10"

enum State {OPEN,CLOSED,FILTERED};

struct ipheader {
    unsigned char      iph_ihl:5, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};
// total udp header length: 8 bytes (=64 bits)

//TODO: TCP HEADER DECLARATION

using namespace std;

class Scanner {
    public:
        Scanner(vector<int> &port_vector);
        void run_scan();
        virtual State scan_port(int port) = 0;
        void set_host_ip(string& host);
        void print_header();
        void print_results(string protocol);
    private:
        bool validate_ip(char *host);
        string host_name;
    protected:
        map<State,string> state_map;
        map<int,State> results_map;
        vector<int>& ports;
        char host_ip[16];
};


#endif //IPK_SCAN_SCANNER_H
