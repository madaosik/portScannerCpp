//
// Created by Adam Láníček on 2019-04-01.
//

#include "argparser.h"

ArgParser::ArgParser (int argc, char **argv)
{
        argCnt = argc - 1;
        args = vector<string>(argv, argv + argc);
}



