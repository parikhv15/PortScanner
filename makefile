
all:
	g++ -Wall -o portScanner portScanner.cpp ps_setup.cpp DestIp.cpp -g -lpthread
