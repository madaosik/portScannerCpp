//
// Created by Adam Láníček on 2019-04-01.
//

#include <iostream>
#include <vector>
#include <string>
#include "Argparser.h"
#include "Logger.h"
#include "TcpScanner.h"
#include "UdpScanner.h"

#define DEBUG false

int main (int argc, char **argv) {
    bool header_missing = true;
    ArgParser argsContainer = ArgParser(argc, argv);
    Logger::change_debug_status(DEBUG);
    vector<int>& tcpPorts = argsContainer.getTcpPorts();

    if (!tcpPorts.empty()) {
        TcpScanner tcpScanner = TcpScanner(tcpPorts);
        tcpScanner.set_host_ip(argsContainer.getHost());
        tcpScanner.print_header();
        header_missing = false;
        tcpScanner.run_scan();
        tcpScanner.print_results(std::string("/tcp"));
        // print the outcome
    }

    vector<int>& udpPorts = argsContainer.getUdpPorts();
    if (!udpPorts.empty()) {
        UdpScanner udpScanner = UdpScanner(udpPorts);
        udpScanner.set_host_ip(argsContainer.getHost());
        if (header_missing) { udpScanner.print_header(); }
        udpScanner.run_scan();
        udpScanner.print_results(std::string("/udp"));
        // print the outcome
    }
    return 0;
}