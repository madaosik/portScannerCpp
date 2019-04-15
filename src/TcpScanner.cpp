//
// Created by Adam Láníček on 2019-04-14.
//

#include "TcpScanner.h"

TcpScanner::TcpScanner(vector<int>& ports) : Scanner(ports) {}

State TcpScanner::scan_port(int port) {
    State state = OPEN;
    return state;
}



