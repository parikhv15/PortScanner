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
#include "ps_setup.h"

using namespace std;

//Auxillary method to parse arguments

int __parse_args(ps_args_t *ps_args, char c, char* arg) {

	ifstream ipfile;

	char *pch;
	char* ip_line;
	char temp[IP_SIZE];
	char *pch_t;
	string temp_ip;

	int p_off = 0;
	int p_start = 0;
	int p_stop = 0;

	long mask = 0;
	long start_addr = 0;

	in_addr_t address;
	in_addr s_address;

	vector<string> temp_ports;

	ip_line = (char *) malloc(sizeof(char) * IP_SIZE);

	switch (c) {

	case 'f':
		memset(temp, 0, IP_SIZE);

		ipfile.open(arg, ifstream::in);

		if (!ipfile) {
			cout << "Invalid File Name" << endl << endl;
			usage(stdout);
			exit(0);
		}
		while (!ipfile.eof()) {

			ipfile.getline(ip_line, IP_SIZE);

			if (strlen(ip_line) > 15) {
				cout << "Invalid IP Address" << endl << endl;
				usage(stdout);
				exit(0);
			}

			memcpy(temp, ip_line, strlen(ip_line));

			pch = strtok(temp, ".");

			while (pch != NULL) {

				if (atoi(pch) > 255) {
					cout << "Invalid IP Address" << endl << endl;
					usage(stdout);
					exit(0);
				}
				pch = strtok(NULL, ".");
			}
			ps_args->ip.push_back(ip_line);
			memset(ip_line, 0, IP_SIZE);
			memset(temp, 0, IP_SIZE);
		}
		ps_args->ip.pop_back();
		ipfile.close();
		break;

	case 'i':
		memset(temp, 0, IP_SIZE);

		if (strlen(arg) > 15) {
			cout << "Invalid IP Address" << endl << endl;
			usage(stdout);
			exit(0);
		}
		memcpy(temp, arg, strlen(arg));

		pch = strtok(temp, ".");

		while (pch != NULL) {
			if (atoi(pch) > 255) {
				cout << "Invalid IP Address" << endl << endl;
				usage(stdout);
				exit(0);
			}
			pch = strtok(NULL, ".");

		}
		ps_args->ip.push_back(arg);
		break;

	case 'x':
		memset(temp, 0, IP_SIZE);

		memcpy(temp, arg, strlen(arg));

		pch_t = strtok(temp, "/");

		pch_t = strtok(temp, ".");

		while (pch_t != NULL) {
			if (atoi(pch_t) > 255) {
				cout << endl << "Invalid IP Prefix" << endl << endl;
				usage(stdout);
				exit(0);
			}
			pch_t = strtok(NULL, ".");

		}

		pch = strtok(arg, "/");

		while (pch != NULL) {

			if (strlen(pch) < 3) {
				p_off = atoi(pch);

				if (p_off > 31) {
					cout << endl << "Invalid IP Prefix" << endl << endl;
					usage(stdout);
					exit(0);
				}
			} else {
				ps_args->ip.push_back(pch);
			}
			pch = strtok(NULL, "/");

			if (p_off != 0) {

				mask = ~(0xFFFFFFFF >> p_off);
				address =
						ntohl(
								inet_addr(
										(char*) (ps_args->ip[ps_args->ip.size()
												- 1]).c_str()));
				ps_args->ip.pop_back();
				start_addr = address & mask;
				for (long i = 0; i < pow(2, (32 - p_off)); i++, start_addr++) {
					address = htonl(start_addr);
					s_address.s_addr = address;
					ps_args->ip.push_back(inet_ntoa(s_address));
				}
			}
		}
		if (p_off == 0) {
			cout << endl << "Invalid IP Prefix" << endl << endl;
			usage(stdout);
			exit(0);
		}
		break;
	case 'p':
		pch = strtok(arg, ",");
		while (pch != NULL) {
			if (atoi(pch) > 65536 || atoi(pch) < 0) {
				cout << endl << "Invalid Ports" << endl << endl;
				usage(stdout);
				exit(0);
			}
			temp_ports.push_back(pch);
			pch = strtok(NULL, ",");
		}

		for (vector<string>::iterator it = temp_ports.begin();
				it != temp_ports.end(); ++it) {

			pch = strtok((char *) ((*it).c_str()), "-");

			p_start = atoi(pch);
			while (pch != NULL) {
				p_stop = atoi(pch);
				pch = strtok(NULL, "-");

			}
			if (p_start == p_stop)
				ps_args->ports.push_back(atoi((*it).c_str()));
			else
				for (int i = p_start; i <= p_stop; i++) {

					if (i > 65536 || i < 0) {
						cout << endl << "Invalid Ports" << endl << endl;
						usage(stdout);
						exit(0);
					}
					ps_args->ports.push_back(i);
				}
		}
		break;

	case 'c':
		if (strcmp(arg, "SYN") == 0 || strcmp(arg, "ACK") == 0
				|| strcmp(arg, "NULL") == 0 || strcmp(arg, "FIN") == 0
				|| strcmp(arg, "UDP") == 0 || strcmp(arg, "XMAS") == 0) {
			ps_args->scan.push_back(arg);
		} else {
			cout << endl << "Invalid Scan Types" << endl << endl;
			usage(stdout);
			exit(0);
		}
		break;
	}
	free(ip_line);
	return 0;
}

//Method to print usage
void usage(FILE * file) {
	fprintf(file, "Port Scanner [OPTIONS] [file] \n"
			"\t --help                            Print this help screen\n"
			"\t --ports <ports to scan>     	   Specify ports to scan\n"
			"\t --ip <IP address to scan>   	   Specify IP Address to scan\n"
			"\t --prefix <IP prefix to scan>      Specify IP Prefix to scan\n"
			"\t --file <File to scan>             Specify File to scan\n"
			"\t --speedup <# of threads>          Specify # of threads to use\n"
			"\t --scan <one or more scan>   	   Specify type of scan\n");
}

//Main method for parsing arguments
void parse_args(int argc, char ** argv, ps_args *ps_args) {

	char c;
	int long_index = 0;
	int count = 0;

	char arg[1024];
	int index = 0;

	ps_args->numOfThread = 1;

	static struct option options[] = { { "help", no_argument, 0, 'h' }, {
			"ports", required_argument, 0, 'p' }, { "ip", required_argument, 0,
			'i' }, { "prefix", required_argument, 0, 'x' }, { "file",
	required_argument, 0, 'f' }, { "speedup", required_argument, 0, 's' }, {
			"scan", required_argument, 0, 'c' }, { 0, 0, 0, 0 } };

	if (argc < 2 || argc > 18) {
		cout << "Invalid Number of Arguments" << endl << endl;
		usage(stdout);
		exit(0);
	}

	while ((c = getopt_long(argc, argv, "hp:i:x:f:s:c:", options, &long_index))
			!= -1) {

		switch (c) {

		case 'h':
			usage(stdout);
			exit(0);
			break;
		case 'p':
			strcpy(arg, optarg);
			__parse_args(ps_args, 'p', arg);
			break;
		case 'i':
			strcpy(arg, optarg);
			__parse_args(ps_args, 'i', arg);
			break;
		case 'x':
			strcpy(arg, optarg);
			__parse_args(ps_args, 'x', arg);
			break;
		case 'f':
			__parse_args(ps_args, 'f', optarg);
			break;
		case 's':
			ps_args->numOfThread = atoi(optarg);
			break;
		case 'c':
			index = optind - 1;
			count = argc + 1;
			while (index < argc) {

				if (argv[index][1] == '-') {
					break;
				} else {
					__parse_args(ps_args, 'c', argv[index]);
					count--;
				}
				index++;
			}
			break;

		default:
			usage(stdout);
			exit(0);
			break;

		}
	}
	count -= optind;
	argv += optind;

	if (count > 0) {
		usage(stdout);
		exit(0);
	}

	if (ps_args->ports.size() == 0) {
		for (int i = 1; i <= 1024; i++) {
			ps_args->ports.push_back(i);
		}
	}

	if (ps_args->scan.size() == 0) {
		ps_args->scan.push_back("SYN");

	}

}


//Method to draw conclusions from set of scan results
Conclusion drawConclusion(DestIp& dipObj, vector<int> ports) {

	Result tResult;
	scanResult tScanMap;
	Conclusion tConclusion;

	tResult = dipObj.getResult();

	for (unsigned int i = 0; i < ports.size(); i++) {

		tScanMap.clear();
		tScanMap = tResult[ports[i]];

		if (tScanMap["SYN"] == "Open" || tScanMap["SYN"] == "Closed"
				|| tScanMap["SYN"] == "Filtered") {

			tConclusion.insert(make_pair(ports[i], tScanMap["SYN"]));
		}

		else if (tScanMap["ACK"] == "UnFiltered") {

			if (tScanMap["UDP"] == "Closed") {
				tConclusion.insert(make_pair(ports[i], "Closed"));
			}

			else if (tScanMap["NULL"] == "Open|Filtered"
					|| tScanMap["FIN"] == "Open|Filtered"
					|| tScanMap["XMAS"] == "Open|Filtered")
				tConclusion.insert(make_pair(ports[i], "UnFiltered"));

			else {
				tConclusion.insert(make_pair(ports[i], "UnFiltered"));
			}

		}

		else if (tScanMap["ACK"] == "Filtered") {
			tConclusion.insert(make_pair(ports[i], "Filtered"));
		}

		else if (tScanMap["UDP"] != "") {

			tConclusion.insert(make_pair(ports[i], tScanMap["UDP"]));

		}

		else if (tScanMap["NULL"] != "" || tScanMap["FIN"] != ""
				|| tScanMap["XMAS"] != "") {

			if (tScanMap["NULL"] != "")
				tConclusion.insert(make_pair(ports[i], tScanMap["NULL"]));
			else if (tScanMap["XMAS"] != "")
				tConclusion.insert(make_pair(ports[i], tScanMap["XMAS"]));
			else if (tScanMap["FIN"] != "")
				tConclusion.insert(make_pair(ports[i], tScanMap["FIN"]));

		}

	}

	return tConclusion;

}


//Method to create port-service map
Service getServiceNames() {

	Service tService;

	tService.insert(make_pair(1, "tcpmux"));
	tService.insert(make_pair(2, "Management Utility"));
	tService.insert(make_pair(3, "Compression Process"));
	tService.insert(make_pair(4, "Unassigned"));
	tService.insert(make_pair(5, "Remote Job Entry"));
	tService.insert(make_pair(6, "Unassigned"));
	tService.insert(make_pair(7, "Echo"));
	tService.insert(make_pair(8, "Unassigned"));
	tService.insert(make_pair(9, "Discard"));
	tService.insert(make_pair(10, "Unassigned"));
	tService.insert(make_pair(11, "Active Users"));
	tService.insert(make_pair(12, "Unassigned"));
	tService.insert(make_pair(13, "Daytime"));
	tService.insert(make_pair(14, "Unassigned"));
	tService.insert(make_pair(15, "Unassigned"));
	tService.insert(make_pair(16, "Unassigned"));
	tService.insert(make_pair(17, "Quote of the Day"));
	tService.insert(make_pair(18, "Msg Send Proto"));
	tService.insert(make_pair(19, "Character Generator"));
	tService.insert(make_pair(20, "ftp-data"));
	tService.insert(make_pair(21, "ftp"));
	tService.insert(make_pair(22, "ssh"));
	tService.insert(make_pair(23, "Telnet"));
	tService.insert(make_pair(24, "any private mail"));
	tService.insert(make_pair(25, "Simple Mail Transfer"));
	tService.insert(make_pair(26, "Unassigned"));
	tService.insert(make_pair(27, "NSW User System FE"));
	tService.insert(make_pair(28, "Unassigned"));
	tService.insert(make_pair(29, "MSG ICP"));
	tService.insert(make_pair(30, "Unassigned"));
	tService.insert(make_pair(31, "MSG Authentication"));
	tService.insert(make_pair(32, "Unassigned"));
	tService.insert(make_pair(33, "DSP"));
	tService.insert(make_pair(34, "Unassigned"));
	tService.insert(make_pair(35, "priv printer server"));
	tService.insert(make_pair(36, "Unassigned"));
	tService.insert(make_pair(37, "Time"));
	tService.insert(make_pair(38, "Route Access Proto"));
	tService.insert(make_pair(39, "RLP"));
	tService.insert(make_pair(40, "Unassigned"));
	tService.insert(make_pair(41, "Graphics"));
	tService.insert(make_pair(42, "Host Name Server"));
	tService.insert(make_pair(43, "Who Is"));
	tService.insert(make_pair(44, "MPM FLAGS Protocol"));
	tService.insert(make_pair(45, "mpm"));
	tService.insert(make_pair(46, "MPM [default send]"));
	tService.insert(make_pair(47, "NI FTP"));
	tService.insert(make_pair(48, "Digital Audit Daemon"));
	tService.insert(make_pair(49, "TACACS"));
	tService.insert(make_pair(50, "re-mail-ck"));
	tService.insert(make_pair(51, ""));
	tService.insert(make_pair(52, "XNS Time Protocol"));
	tService.insert(make_pair(53, "Domain Name Server"));
	tService.insert(make_pair(54, "XNS Clearinghouse"));
	tService.insert(make_pair(55, "ISI Graphics Language"));
	tService.insert(make_pair(56, "XNS Authentication"));
	tService.insert(make_pair(57, "any private terminal"));
	tService.insert(make_pair(58, "XNS Mail"));
	tService.insert(make_pair(59, "priv file serv"));
	tService.insert(make_pair(60, "Unassigned"));
	tService.insert(make_pair(61, "NI MAIL"));
	tService.insert(make_pair(62, "ACA Services"));
	tService.insert(make_pair(63, "whois++"));
	tService.insert(make_pair(64, "covia"));
	tService.insert(make_pair(65, "TACACS-DS"));
	tService.insert(make_pair(66, "Oracle SQL*NET"));
	tService.insert(make_pair(67, "BootstrapPS"));
	tService.insert(make_pair(68, "BootstrapPC"));
	tService.insert(make_pair(69, "TFTP"));
	tService.insert(make_pair(70, "Gopher"));
	tService.insert(make_pair(71, "Remote Job Service"));
	tService.insert(make_pair(72, "Remote Job Service"));
	tService.insert(make_pair(73, "Remote Job Service"));
	tService.insert(make_pair(74, "Remote Job Service"));
	tService.insert(make_pair(75, "priv dialout serv"));
	tService.insert(make_pair(76, "deos"));
	tService.insert(make_pair(77, "private RJE serv"));
	tService.insert(make_pair(78, "vettcp"));
	tService.insert(make_pair(79, "Finger"));
	tService.insert(make_pair(80, "World Wide Web HTTP"));
	tService.insert(make_pair(81, ""));
	tService.insert(make_pair(82, "XFER Utility"));
	tService.insert(make_pair(83, "MIT ML Device"));
	tService.insert(make_pair(84, "CTF"));
	tService.insert(make_pair(85, "MIT ML Device"));
	tService.insert(make_pair(86, "Micro Focus Cobol"));
	tService.insert(make_pair(87, "private term link"));
	tService.insert(make_pair(88, "Kerberos"));
	tService.insert(make_pair(89, "SU/MIT tg"));
	tService.insert(make_pair(90, "DNSIX"));
	tService.insert(make_pair(91, "MIT-Dov"));
	tService.insert(make_pair(92, "NPP"));
	tService.insert(make_pair(93, "DCP"));
	tService.insert(make_pair(94, "objcall"));
	tService.insert(make_pair(95, "SUPDUP"));
	tService.insert(make_pair(96, "DIXIE"));
	tService.insert(make_pair(97, "Swift-RVF"));
	tService.insert(make_pair(98, "TAC News"));
	tService.insert(make_pair(99, "Metagram Relay"));
	tService.insert(make_pair(100, ""));
	tService.insert(make_pair(101, "NIC Host Name Server"));
	tService.insert(make_pair(102, "ISO-TSAP Class 0"));
	tService.insert(make_pair(103, "gppitnp"));
	tService.insert(make_pair(104, "acr-nema"));
	tService.insert(make_pair(105, "CSO"));
	tService.insert(make_pair(106, "3COM-TSMUX"));
	tService.insert(make_pair(107, "RTelnet Service"));
	tService.insert(make_pair(108, "SNAGAS"));
	tService.insert(make_pair(109, "pop2"));
	tService.insert(make_pair(110, "pop3"));
	tService.insert(make_pair(111, "sunrpc"));
	tService.insert(make_pair(112, "mcidas"));
	tService.insert(make_pair(113, "Auth Service"));
	tService.insert(make_pair(114, ""));
	tService.insert(make_pair(115, "sftp"));
	tService.insert(make_pair(116, "ANSA REX Notify"));
	tService.insert(make_pair(117, "UUCP Path Service"));
	tService.insert(make_pair(118, "SQL Services"));
	tService.insert(make_pair(119, "nntp"));
	tService.insert(make_pair(120, "CFDPTKT"));
	tService.insert(make_pair(121, "erpc"));
	tService.insert(make_pair(122, "SMAKYNET"));
	tService.insert(make_pair(123, "N/W Time Proto"));
	tService.insert(make_pair(124, "ANSA REX Trader"));
	tService.insert(make_pair(125, "locus-map"));
	tService.insert(make_pair(126, "NXEdit"));
	tService.insert(make_pair(127, "locus-con"));
	tService.insert(make_pair(128, "gss-xlicen"));
	tService.insert(make_pair(129, "pwdgen"));
	tService.insert(make_pair(130, "cisco FNATIVE"));
	tService.insert(make_pair(131, "cisco TNATIVE"));
	tService.insert(make_pair(132, "cisco SYSMAINT"));
	tService.insert(make_pair(133, "Statistics Service"));
	tService.insert(make_pair(134, "INGRES-NET Service"));
	tService.insert(make_pair(135, "epmap"));
	tService.insert(make_pair(136, "PROFILE Naming Sys"));
	tService.insert(make_pair(137, "NETBIOS Name Serv"));
	tService.insert(make_pair(138, "netbios-dgm"));
	tService.insert(make_pair(139, "netbios-ssn"));
	tService.insert(make_pair(140, "emfis-data"));
	tService.insert(make_pair(141, "emfis-cntl"));
	tService.insert(make_pair(142, "Britton-Lee IDM"));
	tService.insert(make_pair(143, "imap"));
	tService.insert(make_pair(144, "uma"));
	tService.insert(make_pair(145, "UAAC Protocol"));
	tService.insert(make_pair(146, "ISO-IP0"));
	tService.insert(make_pair(147, "ISO-IP"));
	tService.insert(make_pair(148, "Jargon"));
	tService.insert(make_pair(149, "aed-512"));
	tService.insert(make_pair(150, "SQL-NET"));
	tService.insert(make_pair(151, "HEMS"));
	tService.insert(make_pair(152, "bftp"));
	tService.insert(make_pair(153, "SGMP"));
	tService.insert(make_pair(154, "NETSC"));
	tService.insert(make_pair(155, "NETSC"));
	tService.insert(make_pair(156, "SQL Service"));
	tService.insert(make_pair(157, "knet-cmp"));
	tService.insert(make_pair(158, "PCMail Server"));
	tService.insert(make_pair(159, "NSS-Routing"));
	tService.insert(make_pair(160, "SGMP-TRAPS"));
	tService.insert(make_pair(161, "SNMP"));
	tService.insert(make_pair(162, "SNMPTRAP"));
	tService.insert(make_pair(163, "cmip-man"));
	tService.insert(make_pair(164, "cmip-agent"));
	tService.insert(make_pair(165, "Xerox"));
	tService.insert(make_pair(166, "Sirius Systems"));
	tService.insert(make_pair(167, "NAMP"));
	tService.insert(make_pair(168, "RSVD"));
	tService.insert(make_pair(169, "SEND"));
	tService.insert(make_pair(170, "Network PostScript"));
	tService.insert(make_pair(171, "multiplex"));
	tService.insert(make_pair(172, "Network Innovations"));
	tService.insert(make_pair(173, "Xyplex"));
	tService.insert(make_pair(174, "MAILQ"));
	tService.insert(make_pair(175, "VMNET"));
	tService.insert(make_pair(176, "GENRAD-MUX"));
	tService.insert(make_pair(177, "xdmcp"));
	tService.insert(make_pair(178, "NextStep"));
	tService.insert(make_pair(179, "BGP"));
	tService.insert(make_pair(180, "Intergraph"));
	tService.insert(make_pair(181, "Unify"));
	tService.insert(make_pair(182, "Unisys Audit SITP"));
	tService.insert(make_pair(183, "OCBinder"));
	tService.insert(make_pair(184, "OCServer"));
	tService.insert(make_pair(185, "Remote-KIS"));
	tService.insert(make_pair(186, "KIS Protocol"));
	tService.insert(make_pair(187, "aci"));
	tService.insert(make_pair(188, "Plus Five's MUMPS"));
	tService.insert(make_pair(189, "Queued File Trans"));
	tService.insert(make_pair(190, "gacp"));
	tService.insert(make_pair(191, "Prospero"));
	tService.insert(make_pair(192, "osu-nms"));
	tService.insert(make_pair(193, "srmp"));
	tService.insert(make_pair(194, "Internet Relay Chat"));
	tService.insert(make_pair(195, "dn6-nlm-aud"));
	tService.insert(make_pair(196, "dn6-smm-red"));
	tService.insert(make_pair(197, "DLS"));
	tService.insert(make_pair(198, "dls-mon"));
	tService.insert(make_pair(199, "SMUX"));
	tService.insert(make_pair(200, "src"));
	tService.insert(make_pair(200, "src"));
	tService.insert(make_pair(201, "at-rtmp"));
	tService.insert(make_pair(202, "at-nbp"));
	tService.insert(make_pair(203, "at-3"));
	tService.insert(make_pair(204, "at-echo"));
	tService.insert(make_pair(205, "at-5"));
	tService.insert(make_pair(206, "at-zis"));
	tService.insert(make_pair(207, "at-7"));
	tService.insert(make_pair(208, "at-8"));
	tService.insert(make_pair(209, "qmtp"));
	tService.insert(make_pair(210, "z39-50"));
	tService.insert(make_pair(210, "z39.50"));
	tService.insert(make_pair(211, "914c-g"));
	tService.insert(make_pair(211, "914c/g"));
	tService.insert(make_pair(212, "anet"));
	tService.insert(make_pair(213, "ipx"));
	tService.insert(make_pair(214, "vmpwscs"));
	tService.insert(make_pair(215, "softpc"));
	tService.insert(make_pair(216, "CAIlic"));
	tService.insert(make_pair(217, "dbase"));
	tService.insert(make_pair(218, "mpp"));
	tService.insert(make_pair(219, "uarps"));
	tService.insert(make_pair(220, "imap3"));
	tService.insert(make_pair(221, "fln-spx"));
	tService.insert(make_pair(222, "rsh-spx"));
	tService.insert(make_pair(223, "cdc"));
	tService.insert(make_pair(224, "masqdialer"));
	tService.insert(make_pair(242, "direct"));
	tService.insert(make_pair(243, "sur-meas"));
	tService.insert(make_pair(244, "inbusiness"));
	tService.insert(make_pair(245, "link"));
	tService.insert(make_pair(246, "dsp3270"));
	tService.insert(make_pair(247, "subntbcst-tftp"));
	tService.insert(make_pair(247, "subntbcst_tftp"));
	tService.insert(make_pair(248, "bhfhs"));
	tService.insert(make_pair(256, "rap"));
	tService.insert(make_pair(257, "set"));
	tService.insert(make_pair(259, "esro-gen"));
	tService.insert(make_pair(260, "openport"));
	tService.insert(make_pair(261, "nsiiops"));
	tService.insert(make_pair(262, "arcisdms"));
	tService.insert(make_pair(263, "hdap"));
	tService.insert(make_pair(264, "bgmp"));
	tService.insert(make_pair(265, "x-bone-ctl"));
	tService.insert(make_pair(266, "sst"));
	tService.insert(make_pair(267, "td-service"));
	tService.insert(make_pair(268, "td-replica"));
	tService.insert(make_pair(269, "manet"));
	tService.insert(make_pair(270, ""));
	tService.insert(make_pair(271, "pt-tls"));
	tService.insert(make_pair(280, "http-mgmt"));
	tService.insert(make_pair(281, "personal-link"));
	tService.insert(make_pair(282, "cableport-ax"));
	tService.insert(make_pair(283, "rescap"));
	tService.insert(make_pair(284, "corerjd"));
	tService.insert(make_pair(286, "fxp"));
	tService.insert(make_pair(287, "k-block"));
	tService.insert(make_pair(308, "novastorbakcup"));
	tService.insert(make_pair(309, "entrusttime"));
	tService.insert(make_pair(310, "bhmds"));
	tService.insert(make_pair(311, "asip-webadmin"));
	tService.insert(make_pair(312, "vslmp"));
	tService.insert(make_pair(313, "magenta-logic"));
	tService.insert(make_pair(314, "opalis-robot"));
	tService.insert(make_pair(315, "dpsi"));
	tService.insert(make_pair(316, "decauth"));
	tService.insert(make_pair(317, "zannet"));
	tService.insert(make_pair(318, "pkix-timestamp"));
	tService.insert(make_pair(319, "ptp-event"));
	tService.insert(make_pair(320, "ptp-general"));
	tService.insert(make_pair(321, "pip"));
	tService.insert(make_pair(322, "rtsps"));
	tService.insert(make_pair(323, "rpki-rtr"));
	tService.insert(make_pair(324, "rpki-rtr-tls"));
	tService.insert(make_pair(333, "texar"));
	tService.insert(make_pair(344, "pdap"));
	tService.insert(make_pair(345, "pawserv"));
	tService.insert(make_pair(346, "zserv"));
	tService.insert(make_pair(347, "fatserv"));
	tService.insert(make_pair(348, "csi-sgwp"));
	tService.insert(make_pair(349, "mftp"));
	tService.insert(make_pair(350, "matip-type-a"));
	tService.insert(make_pair(351, "matip-type-b"));
	tService.insert(make_pair(351, "bhoetty"));
	tService.insert(make_pair(352, "dtag-ste-sb"));
	tService.insert(make_pair(352, "bhoedap4"));
	tService.insert(make_pair(353, "ndsauth"));
	tService.insert(make_pair(354, "bh611"));
	tService.insert(make_pair(355, "datex-asn"));
	tService.insert(make_pair(356, "cloanto-net-1"));
	tService.insert(make_pair(357, "bhevent"));
	tService.insert(make_pair(358, "shrinkwrap"));
	tService.insert(make_pair(359, "nsrmp"));
	tService.insert(make_pair(360, "scoi2odialog"));
	tService.insert(make_pair(361, "semantix"));
	tService.insert(make_pair(362, "srssend"));
	tService.insert(make_pair(363, "rsvp-tunnel"));
	tService.insert(make_pair(363, "rsvp_tunnel"));
	tService.insert(make_pair(364, "aurora-cmgr"));
	tService.insert(make_pair(365, "dtk"));
	tService.insert(make_pair(366, "odmr"));
	tService.insert(make_pair(367, "mortgageware"));
	tService.insert(make_pair(368, "qbikgdp"));
	tService.insert(make_pair(369, "rpc2portmap"));
	tService.insert(make_pair(370, "codaauth2"));
	tService.insert(make_pair(371, "clearcase"));
	tService.insert(make_pair(372, "ulistproc"));
	tService.insert(make_pair(373, "legent-1"));
	tService.insert(make_pair(374, "legent-2"));
	tService.insert(make_pair(375, "hassle"));
	tService.insert(make_pair(376, "nip"));
	tService.insert(make_pair(377, "tnETOS"));
	tService.insert(make_pair(378, "dsETOS"));
	tService.insert(make_pair(379, "is99c"));
	tService.insert(make_pair(380, "is99s"));
	tService.insert(make_pair(381, "hp-collector"));
	tService.insert(make_pair(382, "hp-managed-node"));
	tService.insert(make_pair(383, "hp-alarm-mgr"));
	tService.insert(make_pair(384, "arns"));
	tService.insert(make_pair(385, "ibm-app"));
	tService.insert(make_pair(386, "asa"));
	tService.insert(make_pair(387, "aurp"));
	tService.insert(make_pair(388, "unidata-ldm"));
	tService.insert(make_pair(389, "ldap"));
	tService.insert(make_pair(390, "uis"));
	tService.insert(make_pair(391, "synotics-relay"));
	tService.insert(make_pair(392, "synotics-broker"));
	tService.insert(make_pair(393, "meta5"));
	tService.insert(make_pair(394, "embl-ndt"));
	tService.insert(make_pair(395, "netcp"));
	tService.insert(make_pair(396, "netware-ip"));
	tService.insert(make_pair(397, "mptn"));
	tService.insert(make_pair(398, "kryptolan"));
	tService.insert(make_pair(399, "iso-tsap-c2"));
	tService.insert(make_pair(400, "osb-sd"));
	tService.insert(make_pair(401, "ups"));
	tService.insert(make_pair(402, "genie"));
	tService.insert(make_pair(403, "decap"));
	tService.insert(make_pair(404, "nced"));
	tService.insert(make_pair(405, "ncld"));
	tService.insert(make_pair(406, "imsp"));
	tService.insert(make_pair(407, "timbuktu"));
	tService.insert(make_pair(408, "prm-sm"));
	tService.insert(make_pair(409, "prm-nm"));
	tService.insert(make_pair(410, "decladebug"));
	tService.insert(make_pair(411, "rmt"));
	tService.insert(make_pair(412, "synoptics-trap"));
	tService.insert(make_pair(413, "smsp"));
	tService.insert(make_pair(414, "infoseek"));
	tService.insert(make_pair(415, "bnet"));
	tService.insert(make_pair(416, "silverplatter"));
	tService.insert(make_pair(417, "onmux"));
	tService.insert(make_pair(418, "hyper-g"));
	tService.insert(make_pair(419, "ariel1"));
	tService.insert(make_pair(420, "smpte"));
	tService.insert(make_pair(421, "ariel2"));
	tService.insert(make_pair(422, "ariel3"));
	tService.insert(make_pair(423, "opc-job-start"));
	tService.insert(make_pair(424, "opc-job-track"));
	tService.insert(make_pair(425, "icad-el"));
	tService.insert(make_pair(426, "smartsdp"));
	tService.insert(make_pair(427, "svrloc"));
	tService.insert(make_pair(428, "ocs-cmu"));
	tService.insert(make_pair(428, "ocs_cmu"));
	tService.insert(make_pair(429, "ocs-amu"));
	tService.insert(make_pair(429, "ocs_amu"));
	tService.insert(make_pair(430, "utmpsd"));
	tService.insert(make_pair(431, "utmpcd"));
	tService.insert(make_pair(432, "iasd"));
	tService.insert(make_pair(433, "nnsp"));
	tService.insert(make_pair(434, "mobileip-agent"));
	tService.insert(make_pair(435, "mobilip-mn"));
	tService.insert(make_pair(436, "dna-cml"));
	tService.insert(make_pair(437, "comscm"));
	tService.insert(make_pair(438, "dsfgw"));
	tService.insert(make_pair(439, "dasp"));
	tService.insert(make_pair(440, "sgcp"));
	tService.insert(make_pair(441, "decvms-sysmgt"));
	tService.insert(make_pair(442, "cvc-hostd"));
	tService.insert(make_pair(442, "cvc_hostd"));
	tService.insert(make_pair(443, "https"));
	tService.insert(make_pair(444, "snpp"));
	tService.insert(make_pair(445, "microsoft-ds"));
	tService.insert(make_pair(446, "ddm-rdb"));
	tService.insert(make_pair(447, "ddm-dfm"));
	tService.insert(make_pair(448, "ddm-ssl"));
	tService.insert(make_pair(449, "as-servermap"));
	tService.insert(make_pair(450, "tserver"));
	tService.insert(make_pair(451, "sfs-smp-net"));
	tService.insert(make_pair(452, "sfs-config"));
	tService.insert(make_pair(453, "creativeserver"));
	tService.insert(make_pair(454, "contentserver"));
	tService.insert(make_pair(455, "creativepartnr"));
	tService.insert(make_pair(456, "macon-tcp"));
	tService.insert(make_pair(457, "scohelp"));
	tService.insert(make_pair(458, "appleqtc"));
	tService.insert(make_pair(459, "ampr-rcmd"));
	tService.insert(make_pair(460, "skronk"));
	tService.insert(make_pair(461, "datasurfsrv"));
	tService.insert(make_pair(462, "datasurfsrvsec"));
	tService.insert(make_pair(463, "alpes"));
	tService.insert(make_pair(464, "kpasswd"));
	tService.insert(make_pair(465, "urd"));
	tService.insert(make_pair(466, "digital-vrc"));
	tService.insert(make_pair(467, "mylex-mapd"));
	tService.insert(make_pair(468, "photuris"));
	tService.insert(make_pair(469, "rcp"));
	tService.insert(make_pair(470, "scx-proxy"));
	tService.insert(make_pair(471, "mondex"));
	tService.insert(make_pair(472, "ljk-login"));
	tService.insert(make_pair(473, "hybrid-pop"));
	tService.insert(make_pair(474, "tn-tl-w1"));
	tService.insert(make_pair(475, "tcpnethaspsrv"));
	tService.insert(make_pair(476, "tn-tl-fd1"));
	tService.insert(make_pair(477, "ss7ns"));
	tService.insert(make_pair(478, "spsc"));
	tService.insert(make_pair(479, "iafserver"));
	tService.insert(make_pair(480, "iafdbase"));
	tService.insert(make_pair(481, "ph"));
	tService.insert(make_pair(482, "bgs-nsi"));
	tService.insert(make_pair(483, "ulpnet"));
	tService.insert(make_pair(484, "integra-sme"));
	tService.insert(make_pair(485, "powerburst"));
	tService.insert(make_pair(486, "avian"));
	tService.insert(make_pair(487, "saft"));
	tService.insert(make_pair(488, "gss-http"));
	tService.insert(make_pair(489, "nest-protocol"));
	tService.insert(make_pair(490, "micom-pfs"));
	tService.insert(make_pair(491, "go-login"));
	tService.insert(make_pair(492, "ticf-1"));
	tService.insert(make_pair(493, "ticf-2"));
	tService.insert(make_pair(494, "pov-ray"));
	tService.insert(make_pair(495, "intecourier"));
	tService.insert(make_pair(496, "pim-rp-disc"));
	tService.insert(make_pair(497, "retrospect"));
	tService.insert(make_pair(498, "siam"));
	tService.insert(make_pair(499, "iso-ill"));
	tService.insert(make_pair(500, "isakmp"));
	tService.insert(make_pair(501, "stmf"));
	tService.insert(make_pair(502, "mbap"));
	tService.insert(make_pair(503, "intrinsa"));
	tService.insert(make_pair(504, "citadel"));
	tService.insert(make_pair(505, "mailbox-lm"));
	tService.insert(make_pair(506, "ohimsrv"));
	tService.insert(make_pair(507, "crs"));
	tService.insert(make_pair(508, "xvttp"));
	tService.insert(make_pair(509, "snare"));
	tService.insert(make_pair(510, "fcp"));
	tService.insert(make_pair(511, "passgo"));
	tService.insert(make_pair(512, "exec"));
	tService.insert(make_pair(513, "login"));
	tService.insert(make_pair(514, "shell"));
	tService.insert(make_pair(515, "printer"));
	tService.insert(make_pair(516, "videotex"));
	tService.insert(make_pair(517, "talk"));
	tService.insert(make_pair(518, "ntalk"));
	tService.insert(make_pair(519, "utime"));
	tService.insert(make_pair(520, "efs"));
	tService.insert(make_pair(521, "ripng"));
	tService.insert(make_pair(522, "ulp"));
	tService.insert(make_pair(523, "ibm-db2"));
	tService.insert(make_pair(524, "ncp"));
	tService.insert(make_pair(525, "timed"));
	tService.insert(make_pair(526, "tempo"));
	tService.insert(make_pair(527, "stx"));
	tService.insert(make_pair(528, "custix"));
	tService.insert(make_pair(529, "irc-serv"));
	tService.insert(make_pair(530, "courier"));
	tService.insert(make_pair(531, "conference"));
	tService.insert(make_pair(532, "netnews"));
	tService.insert(make_pair(533, "netwall"));
	tService.insert(make_pair(534, "windream"));
	tService.insert(make_pair(535, "iiop"));
	tService.insert(make_pair(536, "opalis-rdv"));
	tService.insert(make_pair(537, "nmsp"));
	tService.insert(make_pair(538, "gdomap"));
	tService.insert(make_pair(539, "apertus-ldp"));
	tService.insert(make_pair(540, "uucp"));
	tService.insert(make_pair(541, "uucp-rlogin"));
	tService.insert(make_pair(542, "commerce"));
	tService.insert(make_pair(543, "klogin"));
	tService.insert(make_pair(544, "kshell"));
	tService.insert(make_pair(545, "appleqtcsrvr"));
	tService.insert(make_pair(546, "dhcpv6-client"));
	tService.insert(make_pair(547, "dhcpv6-server"));
	tService.insert(make_pair(548, "afpovertcp"));
	tService.insert(make_pair(549, "idfp"));
	tService.insert(make_pair(550, "new-rwho"));
	tService.insert(make_pair(551, "cybercash"));
	tService.insert(make_pair(552, "devshr-nts"));
	tService.insert(make_pair(553, "pirp"));
	tService.insert(make_pair(554, "rtsp"));
	tService.insert(make_pair(555, "dsf"));
	tService.insert(make_pair(556, "remotefs"));
	tService.insert(make_pair(557, "openvms-sysipc"));
	tService.insert(make_pair(558, "sdnskmp"));
	tService.insert(make_pair(559, "teedtap"));
	tService.insert(make_pair(560, "rmonitor"));
	tService.insert(make_pair(561, "monitor"));
	tService.insert(make_pair(562, "chshell"));
	tService.insert(make_pair(563, "nntps"));
	tService.insert(make_pair(564, "9pfs"));
	tService.insert(make_pair(565, "whoami"));
	tService.insert(make_pair(566, "streettalk"));
	tService.insert(make_pair(567, "banyan-rpc"));
	tService.insert(make_pair(568, "ms-shuttle"));
	tService.insert(make_pair(569, "ms-rome"));
	tService.insert(make_pair(570, "meter"));
	tService.insert(make_pair(571, "meter"));
	tService.insert(make_pair(572, "sonar"));
	tService.insert(make_pair(573, "banyan-vip"));
	tService.insert(make_pair(574, "ftp-agent"));
	tService.insert(make_pair(575, "vemmi"));
	tService.insert(make_pair(576, "ipcd"));
	tService.insert(make_pair(577, "vnas"));
	tService.insert(make_pair(578, "ipdd"));
	tService.insert(make_pair(579, "decbsrv"));
	tService.insert(make_pair(580, "sntp-heartbeat"));
	tService.insert(make_pair(581, "bdp"));
	tService.insert(make_pair(582, "scc-security"));
	tService.insert(make_pair(583, "philips-vc"));
	tService.insert(make_pair(584, "keyserver"));
	tService.insert(make_pair(586, "password-chg"));
	tService.insert(make_pair(587, "submission"));
	tService.insert(make_pair(588, "cal"));
	tService.insert(make_pair(589, "eyelink"));
	tService.insert(make_pair(590, "tns-cml"));
	tService.insert(make_pair(591, "http-alt"));
	tService.insert(make_pair(592, "eudora-set"));
	tService.insert(make_pair(593, "http-rpc-epmap"));
	tService.insert(make_pair(594, "tpip"));
	tService.insert(make_pair(595, "cab-protocol"));
	tService.insert(make_pair(596, "smsd"));
	tService.insert(make_pair(597, "ptcnameservice"));
	tService.insert(make_pair(598, "sco-websrvrmg3"));
	tService.insert(make_pair(599, "acp"));
	tService.insert(make_pair(600, "ipcserver"));
	tService.insert(make_pair(601, "syslog-conn"));
	tService.insert(make_pair(602, "xmlrpc-beep"));
	tService.insert(make_pair(603, "idxp"));
	tService.insert(make_pair(604, "tunnel"));
	tService.insert(make_pair(605, "soap-beep"));
	tService.insert(make_pair(606, "urm"));
	tService.insert(make_pair(607, "nqs"));
	tService.insert(make_pair(608, "sift-uft"));
	tService.insert(make_pair(609, "npmp-trap"));
	tService.insert(make_pair(610, "npmp-local"));
	tService.insert(make_pair(611, "npmp-gui"));
	tService.insert(make_pair(612, "hmmp-ind"));
	tService.insert(make_pair(613, "hmmp-op"));
	tService.insert(make_pair(614, "sshell"));
	tService.insert(make_pair(615, "sco-inetmgr"));
	tService.insert(make_pair(616, "sco-sysmgr"));
	tService.insert(make_pair(617, "sco-dtmgr"));
	tService.insert(make_pair(618, "dei-icda"));
	tService.insert(make_pair(619, "compaq-evm"));
	tService.insert(make_pair(620, "sco-websrvrmgr"));
	tService.insert(make_pair(621, "escp-ip"));
	tService.insert(make_pair(622, "collaborator"));
	tService.insert(make_pair(623, "oob-ws-http"));
	tService.insert(make_pair(624, "cryptoadmin"));
	tService.insert(make_pair(625, "dec-dlm"));
	tService.insert(make_pair(625, "dec_dlm"));
	tService.insert(make_pair(626, "asia"));
	tService.insert(make_pair(627, "passgo-tivoli"));
	tService.insert(make_pair(628, "qmqp"));
	tService.insert(make_pair(629, "3com-amp3"));
	tService.insert(make_pair(630, "rda"));
	tService.insert(make_pair(631, "ipp"));
	tService.insert(make_pair(632, "bmpp"));
	tService.insert(make_pair(633, "servstat"));
	tService.insert(make_pair(634, "ginad"));
	tService.insert(make_pair(635, "rlzdbase"));
	tService.insert(make_pair(636, "ldaps"));
	tService.insert(make_pair(637, "lanserver"));
	tService.insert(make_pair(638, "mcns-sec"));
	tService.insert(make_pair(639, "msdp"));
	tService.insert(make_pair(640, "entrust-sps"));
	tService.insert(make_pair(641, "repcmd"));
	tService.insert(make_pair(642, "esro-emsdp"));
	tService.insert(make_pair(643, "sanity"));
	tService.insert(make_pair(644, "dwr"));
	tService.insert(make_pair(645, "pssc"));
	tService.insert(make_pair(646, "ldp"));
	tService.insert(make_pair(647, "dhcp-failover"));
	tService.insert(make_pair(648, "rrp"));
	tService.insert(make_pair(649, "cadview-3d"));
	tService.insert(make_pair(650, "obex"));
	tService.insert(make_pair(651, "ieee-mms"));
	tService.insert(make_pair(652, "hello-port"));
	tService.insert(make_pair(653, "repscmd"));
	tService.insert(make_pair(654, "aodv"));
	tService.insert(make_pair(655, "tinc"));
	tService.insert(make_pair(656, "spmp"));
	tService.insert(make_pair(657, "rmc"));
	tService.insert(make_pair(658, "tenfold"));
	tService.insert(make_pair(660, "mac-srvr-admin"));
	tService.insert(make_pair(661, "hap"));
	tService.insert(make_pair(662, "pftp"));
	tService.insert(make_pair(663, "purenoise"));
	tService.insert(make_pair(664, "oob-ws-https"));
	tService.insert(make_pair(665, "sun-dr"));
	tService.insert(make_pair(666, "mdqs"));
	tService.insert(make_pair(666, "doom"));
	tService.insert(make_pair(667, "disclose"));
	tService.insert(make_pair(668, "mecomm"));
	tService.insert(make_pair(669, "meregister"));
	tService.insert(make_pair(670, "vacdsm-sws"));
	tService.insert(make_pair(671, "vacdsm-app"));
	tService.insert(make_pair(672, "vpps-qua"));
	tService.insert(make_pair(673, "cimplex"));
	tService.insert(make_pair(674, "acap"));
	tService.insert(make_pair(675, "dctp"));
	tService.insert(make_pair(676, "vpps-via"));
	tService.insert(make_pair(677, "vpp"));
	tService.insert(make_pair(678, "ggf-ncp"));
	tService.insert(make_pair(679, "mrm"));
	tService.insert(make_pair(680, "entrust-aaas"));
	tService.insert(make_pair(681, "entrust-aams"));
	tService.insert(make_pair(682, "xfr"));
	tService.insert(make_pair(683, "corba-iiop"));
	tService.insert(make_pair(684, "corba-iiop-ssl"));
	tService.insert(make_pair(685, "mdc-portmapper"));
	tService.insert(make_pair(686, "hcp-wismar"));
	tService.insert(make_pair(687, "asipregistry"));
	tService.insert(make_pair(688, "realm-rusd"));
	tService.insert(make_pair(689, "nmap"));
	tService.insert(make_pair(690, "vatp"));
	tService.insert(make_pair(691, "msexch-routing"));
	tService.insert(make_pair(692, "hyperwave-isp"));
	tService.insert(make_pair(693, "connendp"));
	tService.insert(make_pair(694, "ha-cluster"));
	tService.insert(make_pair(695, "ieee-mms-ssl"));
	tService.insert(make_pair(696, "rushd"));
	tService.insert(make_pair(697, "uuidgen"));
	tService.insert(make_pair(698, "olsr"));
	tService.insert(make_pair(699, "accessnetwork"));
	tService.insert(make_pair(700, "epp"));
	tService.insert(make_pair(701, "lmp"));
	tService.insert(make_pair(702, "iris-beep"));
	tService.insert(make_pair(704, "elcsd"));
	tService.insert(make_pair(705, "agentx"));
	tService.insert(make_pair(706, "silc"));
	tService.insert(make_pair(707, "borland-dsj"));
	tService.insert(make_pair(709, "entrust-kmsh"));
	tService.insert(make_pair(710, "entrust-ash"));
	tService.insert(make_pair(711, "cisco-tdp"));
	tService.insert(make_pair(712, "tbrpf"));
	tService.insert(make_pair(713, "iris-xpc"));
	tService.insert(make_pair(714, "iris-xpcs"));
	tService.insert(make_pair(715, "iris-lwz"));
	tService.insert(make_pair(729, "netviewdm1"));
	tService.insert(make_pair(730, "netviewdm2"));
	tService.insert(make_pair(731, "netviewdm3"));
	tService.insert(make_pair(741, "netgw"));
	tService.insert(make_pair(742, "netrcs"));
	tService.insert(make_pair(744, "flexlm"));
	tService.insert(make_pair(747, "fujitsu-dev"));
	tService.insert(make_pair(748, "ris-cm"));
	tService.insert(make_pair(749, "kerberos-adm"));
	tService.insert(make_pair(750, "rfile"));
	tService.insert(make_pair(751, "pump"));
	tService.insert(make_pair(752, "qrh"));
	tService.insert(make_pair(753, "rrh"));
	tService.insert(make_pair(754, "tell"));
	tService.insert(make_pair(758, "nlogin"));
	tService.insert(make_pair(759, "con"));
	tService.insert(make_pair(760, "ns"));
	tService.insert(make_pair(761, "rxe"));
	tService.insert(make_pair(762, "quotad"));
	tService.insert(make_pair(763, "cycleserv"));
	tService.insert(make_pair(764, "omserv"));
	tService.insert(make_pair(765, "webster"));
	tService.insert(make_pair(767, "phonebook"));
	tService.insert(make_pair(769, "vid"));
	tService.insert(make_pair(770, "cadlock"));
	tService.insert(make_pair(771, "rtip"));
	tService.insert(make_pair(772, "cycleserv2"));
	tService.insert(make_pair(773, "submit"));
	tService.insert(make_pair(774, "rpasswd"));
	tService.insert(make_pair(775, "entomb"));
	tService.insert(make_pair(776, "wpages"));
	tService.insert(make_pair(777, "multiling-http"));
	tService.insert(make_pair(780, "wpgs"));
	tService.insert(make_pair(800, "mdbs-daemon"));
	tService.insert(make_pair(800, "mdbs_daemon"));
	tService.insert(make_pair(801, "device"));
	tService.insert(make_pair(802, "mbap-s"));
	tService.insert(make_pair(810, "fcp-udp"));
	tService.insert(make_pair(828, "itm-mcell-s"));
	tService.insert(make_pair(829, "pkix-3-ca-ra"));
	tService.insert(make_pair(830, "netconf-ssh"));
	tService.insert(make_pair(831, "netconf-beep"));
	tService.insert(make_pair(832, "netconfsoaphttp"));
	tService.insert(make_pair(833, "netconfsoapbeep"));
	tService.insert(make_pair(847, "dhcp-failover2"));
	tService.insert(make_pair(848, "gdoi"));
	tService.insert(make_pair(860, "iscsi"));
	tService.insert(make_pair(861, "owamp-control"));
	tService.insert(make_pair(862, "twamp-control"));
	tService.insert(make_pair(873, "rsync"));
	tService.insert(make_pair(886, "iclcnet-locate"));
	tService.insert(make_pair(887, "iclcnet-svinfo"));
	tService.insert(make_pair(887, "iclcnet_svinfo"));
	tService.insert(make_pair(888, "accessbuilder"));
	tService.insert(make_pair(888, "cddbp"));
	tService.insert(make_pair(900, "omginitialrefs"));
	tService.insert(make_pair(901, "smpnameres"));
	tService.insert(make_pair(902, "ideafarm-door"));
	tService.insert(make_pair(903, "ideafarm-panic"));
	tService.insert(make_pair(910, "kink"));
	tService.insert(make_pair(911, "xact-backup"));
	tService.insert(make_pair(912, "apex-mesh"));
	tService.insert(make_pair(913, "apex-edge"));
	tService.insert(make_pair(989, "ftps-data"));
	tService.insert(make_pair(990, "ftps"));
	tService.insert(make_pair(991, "nas"));
	tService.insert(make_pair(992, "telnets"));
	tService.insert(make_pair(993, "imaps"));
	tService.insert(make_pair(994, "Reserved"));
	tService.insert(make_pair(995, "pop3s"));
	tService.insert(make_pair(996, "vsinet"));
	tService.insert(make_pair(997, "maitrd"));
	tService.insert(make_pair(998, "busboy"));
	tService.insert(make_pair(999, "garcon"));
	tService.insert(make_pair(999, "puprouter"));
	tService.insert(make_pair(1000, "cadlock2"));
	tService.insert(make_pair(1010, "surf"));
	tService.insert(make_pair(1021, "exp1"));
	tService.insert(make_pair(1022, "exp2"));
	tService.insert(make_pair(1023, "Reserved"));
	tService.insert(make_pair(1024, "Reserved"));

	return tService;
}
