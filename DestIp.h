/*
 * DestIp.h
 *
 *  Created on: Nov 20, 2014
 *      Author: marshal
 */

#ifndef DESTIP_H_
#define DESTIP_H_
#include <map>
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
#include <iomanip>
#include <netinet/udp.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <functional>
#include <poll.h>

#define PKLEN 8192
#define IPLEN 32
#define RCVPKT 90
#define QLEN 12

using namespace std;

typedef map<string, string> scanResult;
typedef map<int, scanResult> Result;
typedef map<int, string> Version;
typedef map<int, string> Conclusion;

typedef struct checksum {
	u_int32_t s_addr;
	u_int32_t d_addr;
	u_int8_t ph;
	u_int8_t proto;
	u_int16_t len;
} checksum_t;

typedef struct dnshdr {
	unsigned short id;
	unsigned char rd :1;
	unsigned char tc :1;
	unsigned char aa :1;
	unsigned char opcode :4;
	unsigned char qr :1;
	unsigned char rcode :4;
	unsigned char cd :1;
	unsigned char ad :1;
	unsigned char z :1;
	unsigned char ra :1;
	unsigned short q_count;
	unsigned short ans_count;
	unsigned short auth_count;
	unsigned short add_count;
} dnshdr_t;

typedef struct ques {
	unsigned short qtype;
	unsigned short qclass;
} ques_t;

class DestIp {

	string destip;
	int destPort;
	string scan;
	Result result;
	string port_status;
	int printFlag;
	int retransmitFlag;
	int s_port;
	string version;
	Version mapVer;
	Conclusion conclusion;
	string source_ip;

public:
	unsigned short getChecksum(unsigned short *ptr, int noOfBytes);
	DestIp(string destIp, int destport, string scann, string source_ip);
	DestIp();
	DestIp(const DestIp&);
	virtual ~DestIp();
	string getDestIp();
	string getScan();
	int getDestPort();
	Result getResult();
	void setResult(Result result);
	void setDestIp(string ip);
	void setScan(string scan);
	void setDestPort(int port);
	string getSourceIP();
	void performScan();
	int sendTCPPkt(int sock, char* packet_s, sockaddr_in sin);
	int sendUDPPkt(int sock, char* packet_s, sockaddr_in sin);
	int rcvTCPPkt(int sock, int sock_icmp, char *packet_r, int port,
			string scan);
	int rcvUDPPkt(int sock, int sock_icmp, char *packet_r, int port,
			string scan);
	void printResult(int port, string scan);
	void createTCPPkt(int port, string ip, char * source_ip, char * packet_s,
			string scan);
	void createUDPPkt(int port, string ip, char * source_ip, char * packet_s,
			string scan);
	string getPortStatus();
	void setPortStatus(string portStatus);
	string getVersion();
	Version getVersionMap();
	void setVersionMap(Version vmap);
	void setConclusion(Conclusion cmap);
	Conclusion getConclusion();
};

class threadArgs {

public:
	vector<DestIp> vDestIp;
	int count;
};

#endif /* DESTIP_H_ */
