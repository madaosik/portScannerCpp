//
// Created by Adam Láníček on 2019-04-01.
//

#ifndef IPK_SCAN_ARGPARSER_H
#define IPK_SCAN_ARGPARSER_H

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <iostream>

using namespace std;

class ArgParser {
    public:
        ArgParser(int argc, char **argv);

    private:
        int argCnt;
        vector<string> args;
        vector<int> tcpPorts;
        vector<int> udpPorts;
        string domainName;
        string ipAddr;
};

#endif //IPK_SCAN_ARGPARSER_H
