/*
 * DestIp.cpp
 *
 *  Created on: Nov 20, 2014
 *      Author: marshal
 */

#include "DestIp.h"

DestIp::DestIp() {

}

DestIp::DestIp(const DestIp &d) {
	destip = d.destip;
	destPort = d.destPort;
	scan = d.scan;
	printFlag = d.printFlag;
	s_port = d.s_port;
	result = d.result;
	retransmitFlag = d.retransmitFlag;
	port_status = d.port_status;
	version = d.version;
	source_ip = d.source_ip;

}

DestIp::DestIp(string destIp, int destPort, string scan, string source_ip) {

	this->destPort = destPort;
	this->scan = scan;
	this->destip = destIp;
	this->printFlag = 0;
	this->s_port = 0;
	this->retransmitFlag = 3;
	this->version = "";
	this->source_ip = source_ip;
	this->s_port = random() % (65535 - 1025) + 1025;

}

string DestIp::getSourceIP() {

	return this->source_ip;
}

string DestIp::getPortStatus() {
	return this->port_status;
}

void DestIp::setPortStatus(string portStatus) {
	this->port_status = portStatus;
}

DestIp::~DestIp() {


}

int DestIp::getDestPort() {

	return this->destPort;
}

void DestIp::setDestPort(int port) {

	this->destPort = port;
}

string DestIp::getDestIp() {

	return this->destip;
}

void DestIp::setDestIp(string ip) {

	this->destip = ip;
}

string DestIp::getScan() {

	return this->scan;
}

void DestIp::setScan(string scan) {

	this->scan = scan;
}

Result DestIp::getResult() {

	return this->result;
}

void DestIp::setResult(Result result) {

	this->result = result;
}

string DestIp::getVersion() {

	return this->version;

}

Version DestIp::getVersionMap() {

	return this->mapVer;

}

void DestIp::setVersionMap(Version vmap) {

	this->mapVer = vmap;

}

void DestIp::setConclusion(Conclusion cmap) {

	this->conclusion = cmap;
}

Conclusion DestIp::getConclusion() {

	return this->conclusion;

}


//Method to detect service versions of open ports.

string detectServiceVersion(int port, string dip) {

	struct sockaddr_in sin;
	char buffer[512];
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(dip.c_str());
	sin.sin_port = htons(port);
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	int index;
	string version;

	struct timeval timeout;

	timeout.tv_sec = 31;
	timeout.tv_usec = 0;

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout,
			sizeof(timeout)) < 0) {
		perror("Error setting Timeout");
	}
	int conn = connect(sock, (struct sockaddr*) &sin, sizeof(sin));

	if (conn < 0) {

		close(sock);
		return "";
	}

	if (port == 80) {
		if ((send(sock, "GET / HTTP/1.1\r\n\r\n", 25, 0)) > 0) {

		}
	} else if (port == 110) {
		if ((send(sock, "ABCD", 22, 0)) > 0) {

		}
	}

	int rcvdBytes = 0;

	if ((rcvdBytes = recv(sock, buffer, 512, 0)) > 0) {

		version = buffer;
		close(sock);
	} else {
		version = "";
		close(sock);

	}

	memset(buffer, 0, 512);

	if (version.length() > 1) {
		switch (port) {

		case 22:
			index = version.find("\r\n");
			version = version.substr(0, index);
			break;

		case 43:
			index = version.find("Version");
			version = version.substr(index);
			index = version.find("\n");
			version = version.substr(0, index);
			break;

		case 110:
			index = version.find(" ");
			version = version.substr(index + 1);
			index = version.find_last_of(" ");
			version = version.substr(0, index);
			break;

		case 143:
			if (version.length() > 2) {

				index = version.find("IMAP4rev1");
				version = version.substr(index);
				index = version.find(" ");
				version = version.substr(0, index);
			} else {
				version = "";
			}
			break;

		case 80:
			if (version.length() > 8) {
				index = version.find("Server:");
				version = version.substr(index + 8);
				index = version.find("\r\n");
				version = version.substr(0, index);
			} else {
				version = "";
			}
			break;

		case 24:
			index = version.find("P538 DUMBMAIL beta 2a.01c");
			version = version.substr(index);
			index = version.find(";");
			version = version.substr(0, index);
			break;

		}
	} else {
		version.clear();
	}
	return version;
}


//Method to create payload for DNS packet
void createQuery(unsigned char *query) {

	query[0] = (unsigned char) 3;
	query[1] = 'w';
	query[2] = 'w';
	query[3] = 'w';
	query[4] = (unsigned char) 2;
	query[5] = 'i';
	query[6] = 'u';
	query[7] = (unsigned char) 3;
	query[8] = 'e';
	query[9] = 'd';
	query[10] = 'u';
	query[11] = '\0';

}

//Method to calculate checksum

unsigned short DestIp::getChecksum(unsigned short *ptr, int noOfBytes) {

	unsigned int s;
	unsigned short chksum;
	s = 0;
	while (noOfBytes != 0) {

		s += *ptr;
		ptr++;
		noOfBytes -= 2;
	}

	while ((s & (0xffff0000)) != 0) {
		s = ((s & 0xffff0000) >> 16) + (s & 0x0ffff);
	}

	chksum = ~((unsigned short) s);
	return (chksum);
}


//Method to create TCP packets

void DestIp::createTCPPkt(int port, string ip, char * source_ip,
		char * packet_s, string scan) {

	struct iphdr *iph;
	struct tcphdr *tcph;
	struct checksum chk;

	unsigned char *check_data;

	iph = (struct iphdr *) packet_s;
	tcph = (struct tcphdr *) (packet_s + sizeof(iphdr));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph->id = htonl(54321);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = inet_addr(ip.c_str());

	iph->check = getChecksum((unsigned short *) packet_s, iph->tot_len);

	tcph->source = htons(this->s_port);
	tcph->dest = htons(port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;

	tcph->window = htons(5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	if (scan.compare("SYN") == 0) {
		tcph->fin = 0;
		tcph->syn = 1;
		tcph->rst = 0;
		tcph->psh = 0;
		tcph->ack = 0;
		tcph->urg = 0;
	} else if (scan.compare("NULL") == 0) {
		tcph->fin = 0;
		tcph->syn = 0;
		tcph->rst = 0;
		tcph->psh = 0;
		tcph->ack = 0;
		tcph->urg = 0;
	} else if (scan.compare("FIN") == 0) {
		tcph->fin = 1;
		tcph->syn = 0;
		tcph->rst = 0;
		tcph->psh = 0;
		tcph->ack = 0;
		tcph->urg = 0;
	} else if (scan.compare("XMAS") == 0) {
		tcph->fin = 1;
		tcph->syn = 0;
		tcph->rst = 0;
		tcph->psh = 1;
		tcph->ack = 0;
		tcph->urg = 1;
	} else if (scan.compare("ACK") == 0) {
		tcph->fin = 0;
		tcph->syn = 0;
		tcph->rst = 0;
		tcph->psh = 0;
		tcph->ack = 1;
		tcph->urg = 0;
	}
	chk.s_addr = inet_addr(source_ip);
	chk.d_addr = inet_addr(ip.c_str());
	chk.ph = 0;
	chk.proto = IPPROTO_TCP;
	chk.len = htons(sizeof(struct tcphdr));

	int psize = sizeof(struct checksum) + sizeof(struct tcphdr);
	check_data = (unsigned char*) malloc(psize);
	memcpy(check_data, (unsigned char*) &chk, sizeof(struct checksum));
	memcpy(check_data + sizeof(struct checksum), tcph,
			sizeof(struct tcphdr));

	tcph->check = getChecksum((unsigned short*) check_data, psize);

	free(check_data);

}


//Method to create UDP packet

void DestIp::createUDPPkt(int port, string ip, char * source_ip,
		char * packet_s, string scan) {

	struct udphdr *udph;

	udph = (struct udphdr *) (packet_s);

	udph->source = htons(this->s_port);
	udph->dest = htons(port);
	udph->len = htons(sizeof(struct udphdr));
	udph->check = 0;

	if (port == 53) {

		dnshdr_t *dns = (dnshdr_t*) (packet_s + sizeof(udphdr));

		dns->id = htons(54321);
		dns->qr = 0;
		dns->opcode = 0;
		dns->aa = 0;
		dns->tc = 0;
		dns->rd = 1;
		dns->ra = 0;
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = htons(1);
		dns->ans_count = 0;
		dns->auth_count = 0;
		dns->add_count = 0;

		unsigned char *query = (unsigned char*) (packet_s + sizeof(udphdr)
				+ sizeof(dnshdr));

		createQuery(query);

		struct ques *question = (struct ques*) (packet_s + sizeof(udphdr)
				+ sizeof(dnshdr) + strlen((char*) query) + 1);

		question->qclass = htons(1);
		question->qtype = htons(1);

		udph->len = htons(
				sizeof(struct udphdr) + sizeof(struct dnshdr)
						+ strlen((char*) query) + 1 + sizeof(ques));
	}
}

//Method invoked from threads to perform scan.

void DestIp::performScan() {

	char packet_s[PKLEN], packet_r[PKLEN];

	string destip = this->getDestIp();

	string scan = this->getScan();

	int port = this->getDestPort();
	int sock = 0;
	int sock_icmp = 0;
	int val = 1;

	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(destip.c_str());

	while (1) {

		sin.sin_port = htons(port);

		if (scan.compare("UDP") == 0) {

			createUDPPkt(port, destip, (char*) ((this->source_ip).c_str()),
					packet_s, scan);

			sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

			if (sock == -1) {
				perror("Failed to create socket UDP");
				exit(1);
			}

			if (sendUDPPkt(sock, packet_s, sin) < 0) {
				cout << "Packet not sent" << endl;
			} else {
				sock_icmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
			}

			if (rcvUDPPkt(sock, sock_icmp, packet_r, port, scan) <= 0) {
				close(sock);
				close(sock_icmp);
				continue;
			} else {
				this->retransmitFlag = 2;
				break;
			}

		} else {
			createTCPPkt(port, destip, (char*) ((this->source_ip).c_str()),
					packet_s, scan);

			sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

			if (sock == -1) {
				perror("Failed to create socket TCP");
				exit(1);
			}

			if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val))
					< 0) {
				perror("Error setting IP_HDRINCL");
				exit(0);
			}

			if (sendTCPPkt(sock, packet_s, sin) < 0) {
				cout << "Packet not sent" << endl;
			} else {

				sock_icmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
			}
			if (rcvTCPPkt(sock, sock_icmp, packet_r, port, scan) <= 0) {
				close(sock);
				close(sock_icmp);
				continue;
			} else {
				this->retransmitFlag = 2;
				break;
			}
		}
	}
	close(sock_icmp);
	close(sock);
}

//Method to send TCP packet over the network

int DestIp::sendTCPPkt(int sock, char* packet_s, sockaddr_in sin) {

	int tot_len = 0;

	tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);

	if (sendto(sock, packet_s, tot_len, 0, (struct sockaddr *) &sin,
			sizeof(sin)) < 0) {
		cout << "Could not Send" << endl;
		return -1;
	} else {
		return tot_len;
	}
}

//Method to send UDP packet over the network

int DestIp::sendUDPPkt(int sock, char* packet_s, sockaddr_in sin) {

	int tot_len = 0;

	tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);

	struct udphdr* udp = (struct udphdr*) (packet_s);

	if (ntohs(udp->dest) == 53) {
		tot_len = sizeof(struct udphdr) + sizeof(dnshdr) + QLEN + sizeof(ques);
	}

	if (sendto(sock, packet_s, tot_len, 0, (struct sockaddr *) &sin,
			sizeof(sin)) < 0) {
		cout << "Could not Send" << endl;
		return -1;
	} else {
		return tot_len;
	}
}

//Method to receive and analyze TCP packets

int DestIp::rcvTCPPkt(int sock, int sock_icmp, char *packet_r, int port,
		string scan) {

	struct iphdr *iph_r;
	struct tcphdr *tcph_r;
	struct icmphdr *icmph;

	char *destip = (char*) this->getDestIp().c_str();

	int rcvdbytes = 0;
	int ssize = 0;
	int event = 0;

	struct sockaddr saddr;

	ssize = sizeof(saddr);

	struct pollfd fds[2];

	fds[0].fd = sock;
	fds[0].events = POLLIN;

	fds[1].fd = sock_icmp;
	fds[1].events = POLLIN;

	time_t start, stop;

	time(&start);

	while ((event = poll(fds, 2, 4000))) {

		time(&stop);

		if ((float) difftime(stop, start) >= 4.0) {
			event = -1;
			break;
		}

		if ((fds[0].revents & POLLIN) && event > 0
				&& (rcvdbytes = recvfrom(sock, packet_r, RCVPKT, 0, &saddr,
						(socklen_t*) &ssize)) > 0) {
			iph_r = (struct iphdr *) (packet_r);
			tcph_r = (struct tcphdr *) (packet_r + (iph_r->ihl * 4));
			icmph = (struct icmphdr *) (packet_r + (iph_r->ihl * 4));

			if (scan.compare("SYN") == 0) {

				if (iph_r->saddr == inet_addr(destip)
						&& tcph_r->source == htons(port)
						&& (tcph_r->syn == 1 || tcph_r->ack == 1)
						&& ntohs(tcph_r->source) == destPort
						&& ntohs(tcph_r->dest) == s_port && tcph_r->rst != 1) {

					this->port_status = "Open";
					this->retransmitFlag = 0;

					if ((port == 22 || port == 43 || port == 80 || port == 110
							|| port == 143 || port == 24)
							&& (this->getDestIp().compare("129.79.247.87") == 0)) {
						this->version = detectServiceVersion(port,
								this->getDestIp());
					} else {
						this->version = "";
					}

					break;

				} else if (tcph_r->rst == 1 && iph_r->saddr == inet_addr(destip)
						&& ntohs(tcph_r->source) == destPort
						&& ntohs(tcph_r->dest) == s_port) {

					this->port_status = "Closed";
					this->retransmitFlag = 0;

					break;
				}

			} else if (scan.compare("NULL") == 0 || scan.compare("FIN") == 0
					|| scan.compare("XMAS") == 0) {

				if (tcph_r->rst == 1 && iph_r->saddr == inet_addr(destip)
						&& ntohs(tcph_r->source) == destPort
						&& ntohs(tcph_r->dest) == s_port) {

					this->port_status = "Closed";
					this->retransmitFlag = 0;
					break;
				}
			} else if (scan.compare("ACK") == 0) {

				if (tcph_r->rst == 1 && iph_r->saddr == inet_addr(destip)
						&& ntohs(tcph_r->source) == destPort
						&& ntohs(tcph_r->dest) == s_port) {
					this->port_status = "UnFiltered";
					this->retransmitFlag = 0;
					break;
				}
			}
		}
		if ((fds[1].revents & POLLIN) && event > 0
				&& (rcvdbytes = recvfrom(sock_icmp, packet_r, RCVPKT, 0, &saddr,
						(socklen_t*) &ssize)) > 0) {

			iph_r = (struct iphdr *) (packet_r);
			tcph_r = (struct tcphdr *) (packet_r + (iph_r->ihl * 4));
			icmph = (struct icmphdr *) (packet_r + (iph_r->ihl * 4));

			if (scan.compare("SYN") == 0) {

				if (icmph->type == 3
						&& (icmph->code == 1 || icmph->code == 2
								|| icmph->code == 3 || icmph->code == 9
								|| icmph->code == 10 || icmph->code == 13)
						&& iph_r->saddr == inet_addr(destip)) {

					tcph_r = (struct tcphdr*) ((char*) icmph + sizeof(icmphdr)
							+ sizeof(iphdr));

					if (ntohs(tcph_r->source) == s_port
							&& ntohs(tcph_r->dest) == destPort) {

						this->port_status = "Filtered";
						this->retransmitFlag = 0;
						break;
					}
				}

			} else if (scan.compare("NULL") == 0 || scan.compare("FIN") == 0
					|| scan.compare("XMAS") == 0) {

				if (icmph->type == 3
						&& (icmph->code == 1 || icmph->code == 2
								|| icmph->code == 3 || icmph->code == 9
								|| icmph->code == 10 || icmph->code == 13)
						&& iph_r->saddr == inet_addr(destip)) {

					tcph_r = (struct tcphdr*) ((char*) icmph + sizeof(icmphdr)
							+ sizeof(iphdr));

					if (ntohs(tcph_r->source) == s_port
							&& ntohs(tcph_r->dest) == destPort) {

						this->port_status = "Filtered";
						this->retransmitFlag = 0;
						break;
					}
				}
			} else if (scan.compare("ACK") == 0) {

				if (icmph->type == 3
						&& (icmph->code == 1 || icmph->code == 2
								|| icmph->code == 3 || icmph->code == 9
								|| icmph->code == 10 || icmph->code == 13)
						&& iph_r->saddr == inet_addr(destip)) {

					tcph_r = (struct tcphdr*) ((char*) icmph + sizeof(icmphdr)
							+ sizeof(iphdr));

					if (ntohs(tcph_r->source) == s_port
							&& ntohs(tcph_r->dest) == destPort) {

						this->port_status = "Filtered";
						this->retransmitFlag = 0;
						break;
					}
				}
			}
		}
	}

	if (event <= 0) {
		rcvdbytes = -1;
	}

	if (rcvdbytes < 0 && this->retransmitFlag == 0) {
		if (scan.compare("SYN") == 0 || scan.compare("ACK") == 0) {

			this->port_status = "Filtered";
			rcvdbytes = 1;
		}

		else if (scan.compare("NULL") == 0 || scan.compare("FIN") == 0
				|| scan.compare("XMAS") == 0) {
			this->port_status = "Open|Filtered";
			rcvdbytes = 1;
		}
	} else if (rcvdbytes < 0 && this->retransmitFlag > 0) {
		this->retransmitFlag--;
	}
	return rcvdbytes;
}

//Method to receive and analyze UDP packets

int DestIp::rcvUDPPkt(int sock, int sock_icmp, char *packet_r, int port,
		string scan) {

	struct iphdr *iph_r;
	struct udphdr *udph_r;
	struct icmphdr *icmph;

	char *destip = (char*) this->getDestIp().c_str();

	int rcvdbytes = 0;
	int ssize = 0;
	int event = 0;

	struct sockaddr saddr;

	ssize = sizeof(saddr);

	struct pollfd fds[2];

	fds[0].fd = sock;
	fds[0].events = POLLIN;

	fds[1].fd = sock_icmp;
	fds[1].events = POLLIN;

	time_t start, stop;

	time(&start);

	while ((event = poll(fds, 2, ((random() % 7000) + 4000)))) {

		time(&stop);

		if ((float) difftime(stop, start) >= ((random() % 7) + 4)) {
			event = -1;
			break;
		}

		if ((fds[1].revents & POLLIN) && event > 0
				&& (rcvdbytes = recvfrom(sock_icmp, packet_r, RCVPKT, 0, &saddr,
						(socklen_t*) &ssize)) > 0) {

			iph_r = (struct iphdr *) (packet_r);
			udph_r = (struct udphdr *) (packet_r + (iph_r->ihl * 4));
			icmph = (struct icmphdr *) (packet_r + (iph_r->ihl * 4));

			if (icmph->type == 3
					&& (icmph->code == 1 || icmph->code == 2 || icmph->code == 9
							|| icmph->code == 10 || icmph->code == 13)
					&& iph_r->saddr == inet_addr(destip)) {

				udph_r = (struct udphdr*) ((char*) icmph + sizeof(icmphdr)
						+ sizeof(iphdr));

				if (ntohs(udph_r->source) == s_port
						&& ntohs(udph_r->dest) == destPort) {

					this->port_status = "Filtered";
					this->retransmitFlag = 0;
					break;
				}
			} else if ((icmph->type == 3 && icmph->code == 3)
					&& iph_r->saddr == inet_addr(destip)) {

				udph_r = (struct udphdr*) ((char*) icmph + sizeof(icmphdr)
						+ sizeof(iphdr));

				if (ntohs(udph_r->source) == s_port
						&& ntohs(udph_r->dest) == destPort) {

					this->port_status = "Closed";
					this->retransmitFlag = 0;
					break;
				}
			}
		}

		if ((fds[0].revents & POLLIN) && event > 0
				&& (rcvdbytes = recvfrom(sock, packet_r, RCVPKT, 0, &saddr,
						(socklen_t*) &ssize)) > 0) {

			iph_r = (struct iphdr *) (packet_r);
			udph_r = (struct udphdr *) (packet_r + (iph_r->ihl * 4));
			icmph = (struct icmphdr *) (packet_r + (iph_r->ihl * 4));

			if ((ntohs(udph_r->source) == destPort
					&& ntohs(udph_r->dest) == s_port)
					&& iph_r->saddr == inet_addr(destip)) {

				this->port_status = "Open";
				this->retransmitFlag = 0;
				break;

			}
		}
	}
	if (event <= 0) {
		rcvdbytes = -1;
	}

	if (rcvdbytes < 0 && this->retransmitFlag == 0) {
		this->port_status = "Open|Filtered";
		rcvdbytes = 1;
	} else if (rcvdbytes < 0 && this->retransmitFlag > 0) {
		this->retransmitFlag--;
	}
	return rcvdbytes;
}
