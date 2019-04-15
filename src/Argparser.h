//
// Created by Adam Láníček on 2019-04-01.
//

#ifndef IPK_SCAN_ARGPARSER_H
#define IPK_SCAN_ARGPARSER_H

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <getopt.h>
#include <vector>
#include <string>
#include <iostream>

#include "Logger.h"

#define COMMA ","
#define DASH "-"

enum Protocol {TCP,UDP};

using namespace std;

class ArgParser {
    public:
        ArgParser(int argc, char **argv);
        vector<int> &getTcpPorts();
        vector<int> &getUdpPorts();
        string &getHost();
        string &getIface_name();
        void print_tcp_ports();
        void print_udp_ports();

    private:
        bool is_range_valid(string &s);
        void check_port_range(int port);
        bool contains_char(string& s, string& delimiter);
        int convert_to_int(string &s);
        void parse_ports(Protocol protocol, char *port_str);
        vector<int> set_port_values(string &s);
        vector<int> set_port_range(string &s);
        vector<int> tcpPorts;
        vector<int> udpPorts;
        string host;
        string iface_name;
};

#endif //IPK_SCAN_ARGPARSER_H
