#include <iostream>
#include <getopt.h>
#include <string>
#include <fstream>
#include <vector>
#include <pcap.h> 
#include <netinet/ip_icmp.h> 
using namespace std;
int main(int argc, char *argv[])
{
    //arguments parsing using getopt (-r <file> -s <ip|hostname> [-l])
    int current_arg;
    string file_arg = "";
    string host = "";
    bool listen_mode = false;
    while ((current_arg = getopt(argc, argv, "r:s:l")) != -1)
    {
        switch (current_arg)
        {
        case 'r':
        {
            file_arg = optarg;
            continue;
        }
        case 's':
        {
            host = optarg;
            continue;
        }
        case 'l':
        {
            listen_mode = true;
            break;
        }
        case -1:
            break;
        }
    }
    if (file_arg == "" || host == "")
    {
        cerr << "-s and -r options are required" << endl;
        exit(1);
    }
    if (listen_mode) //server
    {
    }
    else //client
    {
        int packet_number = 0;
        string a;
        ifstream source_file(file_arg, ios::in);
        vector<char> buffer(1000);
        while (!source_file.eof())
        {
            source_file.read(buffer.data(), buffer.size());
            streamsize s = source_file.gcount();
            packet_number++;
        }

        source_file.close();





    //ICMP header
    struct icmp icmp_header;
    icmp_header.icmp_type = ICMP_ECHO;
    icmp_header.icmp_code = 0;
    icmp_header.icmp_id = htons(99);
    icmp_header.icmp_seq = htons(packet_number);
    


    icmp_header.icmp_cksum = 0;




    }

    return 0;
}