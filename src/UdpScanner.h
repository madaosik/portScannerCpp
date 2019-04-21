//
// Created by Adam Láníček on 2019-04-14.
//

#ifndef IPK_SCAN_UDPSCANNER_H
#define IPK_SCAN_UDPSCANNER_H

#include <iostream>
#include <vector>
#include "Scanner.h"

using namespace std;

class UdpScanner : public Scanner {
    public:
        UdpScanner(vector<int>& ports, ArgParser& args);
        State scan_port(int port);
    private:
        void create_udp_header(char *packet, int port);

};


#endif //IPK_SCAN_UDPSCANNER_H
