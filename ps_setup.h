#ifndef PS_SETUP_H_

using namespace std;
#define PS_SETUP_H_
#define IP_SIZE 32

#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <fstream>
#include <vector>
#include <bitset>
#include <arpa/inet.h>
#include <unistd.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <map>
#include "DestIp.h"

#define PKLEN 8192
#define IPLEN 32
#define PORTS 1234

typedef struct ps_args {

	vector<string> scan;
	vector<string> ip;
	vector<int> ports;
	unsigned int numOfThread;

} ps_args_t;

typedef map<int, string> Service;

void parse_args(int argc, char ** argv, ps_args *ps_args);
void usage(FILE * file);
Conclusion drawConclusion(DestIp& dipObj, vector<int> ports);
Service getServiceNames();

#endif /* PS_SETUP_H_ */
