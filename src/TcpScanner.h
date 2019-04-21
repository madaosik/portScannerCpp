//
// Created by Adam Láníček on 2019-04-14.
//

#ifndef IPK_SCAN_TCPSCANNER_H
#define IPK_SCAN_TCPSCANNER_H

#include <iostream>
#include <vector>
#include "Scanner.h"

using namespace std;

class TcpScanner : public Scanner {
    public:
        TcpScanner(vector<int>& ports, ArgParser& args);
        State scan_port(int port);
    private:
        void create_tcp_header(char *packet, int port);
};


#endif //IPK_SCAN_TCPSCANNER_H
