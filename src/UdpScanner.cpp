//
// Created by Adam Láníček on 2019-04-14.
//

#include "UdpScanner.h"

UdpScanner::UdpScanner(vector<int>& ports) : Scanner(ports) {}

State UdpScanner::scan_port(int port) {
    State state = OPEN;
    return state;
}

