
#Portscanner
-----------------------

The final development of the Portscanner includes the following files.

Included Files and Purpose:

portScanner.cpp :   Main file where the control loop lives
ps_setup.cpp    :   Contains setup code, such as parsing arguments and creating port to service name map.
DestIp.cpp	:   Contains class and common methods required to perform scan.


ps_setup.h      :   Header file for setup
DestIp.h        :   Header file for DestIp.cpp

================================================================
Tasks Accomplished:

1. The portscanner can scan any port on specified IP address via all TCP scanning techniques.
2. The portscanner can perform UDP scan of any port on specified IP address.
3. The portscanner can analyze the incoming packets and derive conclusions about which ports are open/closed/filtered/unfiltered.
4. The portscanner can verify that ports for SSH, HTTP, SMTP, POP, IMAP, and WHOIS are running these services and retrieve service
   versions from dagwood.soic.indiana.edu.
5. The portscanner can scan IP prefixes and read IP addresses from files.
6. The code is multi-threaded.
================================================================

Steps to compile and run:

1. Navigate to the directory where the makefile and the source code file is present. Make sure they are present at the same
   location.

2. Type make and hit enter.

3. If no error is displayed, run the following command to start scanning:

   ./portScanner [-- ip ip][--ports ports][--prefix prefix][--file file][--scan scan(s)][--speedup speedup]

4. Once the scanning is completed, scan output will be printed on console. In case of any error, the program will be terminated
   with appropriate error messages.



