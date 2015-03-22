#include "ps_setup.h"
#include "DestIp.h"

using namespace std;

unsigned int count;
unsigned int numThreads;
vector<DestIp> result;

pthread_mutex_t mutex_count = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_result = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_numThreads = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_numThreads = PTHREAD_COND_INITIALIZER;


//Method to handle threads.
void * threadPS(void * args) {

	vector<DestIp> vDestIp;
	static int status = 0;

	int localcount = 0;

	vDestIp = ((threadArgs*) args)->vDestIp;

	while (true) {

		pthread_mutex_lock(&mutex_count);
		if (count >= vDestIp.size()) {
			numThreads++;
			status = 1;
			pthread_cond_broadcast(&cond_numThreads);
			pthread_mutex_unlock(&mutex_count);
			pthread_exit(&status);
		} else {
			localcount = count;

			count++;
			pthread_mutex_unlock(&mutex_count);

			vDestIp[localcount].performScan();

			pthread_mutex_lock(&mutex_result);
			result.push_back(vDestIp[localcount]);
			pthread_mutex_unlock(&mutex_result);
		}

	}
	free(args);
	return (void*) &status;
}


//Method to get source IP
void getSourceIp(string sip) {

	int ssock;
	struct sockaddr_in serv, addr;
	unsigned int addrlen = sizeof(addr);
	//char *ip;

	ssock = socket(AF_INET, SOCK_DGRAM, 0);

	serv.sin_addr.s_addr = inet_addr("1.2.3.4");
	serv.sin_family = AF_INET;
	serv.sin_port = htons(80);

	connect(ssock, (sockaddr*) &serv, sizeof(serv));

	getsockname(ssock, (sockaddr*) &addr, &addrlen);

	strcpy((char*) sip.c_str(), inet_ntoa(addr.sin_addr));

	close(ssock);
}

int main(int argc, char** argv) {

	vector<DestIp> vDestIp;
	vector<DestIp> vFinalResultSet;
	Result tResult;
	Version tVersion;
	string tVer;
	string tIp;
	int tdestPort;
	string tScanResult;
	string tScan;
	Conclusion tConclusion;
	time_t start, stop;
	Service mServiceName;
	ps_args_t ps_args;
	threadArgs scanThreads;

	string source_ip;

	pthread_t *threadIds;

	parse_args(argc, argv, &ps_args);

	getSourceIp(source_ip);

	mServiceName = getServiceNames();

	threadIds = new pthread_t[ps_args.numOfThread];

	cout << "Scanning..." << endl;
	cout << endl;

	time(&start);

	for (unsigned int i = 0; i < ps_args.ip.size(); i++) {
		DestIp tDestIp;
		vFinalResultSet.push_back(tDestIp);
		vFinalResultSet[i].setDestIp(ps_args.ip[i]);
	}

	for (vector<string>::iterator ip = ps_args.ip.begin();
			ip != ps_args.ip.end(); ++ip) {
		for (vector<int>::iterator port = ps_args.ports.begin();
				port != ps_args.ports.end(); ++port) {
			for (vector<string>::iterator scan = ps_args.scan.begin();
					scan != ps_args.scan.end(); ++scan) {

				DestIp destIp(*ip, *port, *scan, source_ip);

				vDestIp.push_back(destIp);
				//result.push_back(destIp);
			}
		}
	}

	count = 0;
	numThreads = 0;

	scanThreads.vDestIp = vDestIp;

	for (unsigned int i = 0; i < ps_args.numOfThread; i++) {

		int returnval = pthread_create(&threadIds[i], NULL, threadPS,
				(void*) &scanThreads);

		if (returnval != 0) {
			printf("with thread %lu\n", (unsigned long int) threadIds);
		}

	}

	for (unsigned int i = 0; i < ps_args.numOfThread; i++) {
		pthread_join(threadIds[i], NULL);
	}

	pthread_mutex_lock(&mutex_numThreads);

	while (1) {
		if (numThreads == ps_args.numOfThread) {
			break;
		}
		pthread_cond_wait(&cond_numThreads, &mutex_numThreads);
	}
	pthread_mutex_unlock(&mutex_numThreads);

	time(&stop);
	cout << "Time taken: " << (float) difftime(stop, start) << " seconds"
			<< endl;

	for (unsigned int i = 0; i < vFinalResultSet.size(); i++) {
		tResult.clear();
		tVersion.clear();
		tIp = vFinalResultSet[i].getDestIp();

		for (unsigned int j = 0; j < result.size(); j++) {
			if (tIp.compare(result[j].getDestIp()) == 0) {
				tScanResult = result[j].getPortStatus();
				tdestPort = result[j].getDestPort();
				tScan = result[j].getScan();
				tVer = result[j].getVersion();

				if (tResult.find(tdestPort) == tResult.end()) {
					tResult.insert(make_pair(tdestPort, scanResult()));
				}
				tResult[tdestPort].insert(make_pair(tScan, tScanResult));
				if (tVersion.find(tdestPort) == tVersion.end()) {
					tVersion.insert(make_pair(tdestPort, tVer));
				} else {
					if (tVersion[tdestPort].compare("") == 0) {
						tVersion[tdestPort] = tVer;
					}
				}
			}
		}
		vFinalResultSet[i].setResult(tResult);
		vFinalResultSet[i].setVersionMap(tVersion);
	}

	for (unsigned int i = 0; i < vFinalResultSet.size(); i++) {

		vFinalResultSet[i].setConclusion(
				drawConclusion(vFinalResultSet[i], ps_args.ports));

	}

	int printflag = 0;
	for (unsigned int i = 0; i < vFinalResultSet.size(); i++) {
		tIp = vFinalResultSet[i].getDestIp();
		tResult = vFinalResultSet[i].getResult();
		tVersion = vFinalResultSet[i].getVersionMap();
		tConclusion = vFinalResultSet[i].getConclusion();
		cout << "IP address: " << tIp << endl;
		cout << endl;
		cout << left << setw(10) << "Ports" << setw(20) << "Service Name"
				<< setw(30) << "Version" << setw(25) << "Results" << setw(20)
				<< "Conclusion" << endl;
		cout << setfill('-') << setw(105) << "-" << endl;
		cout << setfill(' ');

		for (unsigned int j = 0; j < ps_args.ports.size(); j++) {
			cout << left << setw(10) << ps_args.ports[j] << setw(20)
					<< mServiceName[ps_args.ports[j]] << setw(30)
					<< tVersion[ps_args.ports[j]];
			printflag = 1;
			for (unsigned int k = 0; k < ps_args.scan.size(); k++) {
				cout << left << ps_args.scan[k] << "("
						<< tResult[ps_args.ports[j]][ps_args.scan[k]]
						<< setw(
								24
										- tResult[ps_args.ports[j]][ps_args.scan[k]].length())
						<< ") ";

				if (printflag) {
					cout << tConclusion[ps_args.ports[j]];

					printflag = 0;

					cout << endl;
					cout << setw(60) << "";
				} else {

					cout << endl;
					cout << setw(60) << "";
				}

			}

			cout << setw(0) << endl;

		}
		cout << setw(0) << endl;

	}
	cout << "Time taken: " << (float) difftime(stop, start) << " seconds"
			<< endl;
	delete[] threadIds;

}

