//
// Created by Adam Láníček on 2019-04-01.
//

#include <iostream>
#include "argparser.h"

int main (int argc, char **argv) {
    std::cout << "Running!\n";
    ArgParser argsContainer = ArgParser(argc, argv);

    return 0;
}