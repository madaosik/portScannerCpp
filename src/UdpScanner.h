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
        UdpScanner(vector<int>& ports);
        State scan_port(int port);
    private:
        unsigned short check_sum(unsigned short *buf, int n_words);
};


#endif //IPK_SCAN_UDPSCANNER_H
