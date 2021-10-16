#include <iostream>
#include <getopt.h>
#include <string>
#include <fstream>
#include <vector>
#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <cstring>
#include <openssl/aes.h>
#include <unistd.h>
#include <unistd.h>
#include <sstream>

using namespace std;

#define ICMP_HEADER_LENGTH 8
#define IPV4_HEADER_LENGTH 20
#define ETHERNET_HEADER_LENGTH 14

// TODO vyfiltrovat pouze packety, které jako destination moje ip
// TODO vyřešit šifrování

char *create_icmp_packet(char *data, int data_length, int icmp_packet_type, int packet_seq_num)
{
    // icmp header
    struct icmp icmp_header;
    icmp_header.icmp_type = icmp_packet_type;
    icmp_header.icmp_code = 0;
    icmp_header.icmp_id = htons(99);
    icmp_header.icmp_seq = htons(packet_seq_num);
    icmp_header.icmp_cksum = 0;

    // allocate memory for packet (header + data)
    char *packet = new char[ICMP_HEADER_LENGTH + data_length];
    // copy header and data to allocated memory
    std::memcpy(packet, &icmp_header, ICMP_HEADER_LENGTH);
    std::memcpy(packet + ICMP_HEADER_LENGTH, data, data_length);

    return packet;
}

vector<char> encrypt_data(vector<char> data)
{
    vector<char> encrypted_buffer(1000);
    AES_KEY aes_key;
    if (AES_set_encrypt_key((unsigned char *)"xkotou06", 128, &aes_key) != 0)
    {
        exit(EXIT_FAILURE); // error handling
    }
    AES_encrypt((unsigned char *)data.data(), (unsigned char *)encrypted_buffer.data(), &aes_key);
    return encrypted_buffer;
}

vector<char> decrypt_data(vector<char> data)
{
    vector<char> decrypted_buffer(1000);
    AES_KEY aes_key;
    if (AES_set_decrypt_key((unsigned char *)"xkotou06", 128, &aes_key) != 0)
    {
        exit(EXIT_FAILURE); // error handling
    }
    AES_decrypt((unsigned char *)data.data(), (unsigned char *)decrypted_buffer.data(), &aes_key);
    return decrypted_buffer;
}

// SERVER functions
// returns default interface - should be first in interfaces list
char *get_default_interface()
{
    pcap_if_t *interfaces;
    char error_buffer[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&interfaces, error_buffer) == -1)
    {
        cerr << error_buffer << endl;
        return (char *)"";
    }
    return interfaces->name; // get first interface (default)
}

int set_pcap_filter(pcap_t *handle, char *interface, char *filter)
{
    // net and mask of device
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char error_buffer[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(interface, &net, &mask, error_buffer) < 0)
    {
        cerr << error_buffer << endl;
        return EXIT_FAILURE;
    }
    struct bpf_program compiled_filter_expression;
    if (pcap_compile(handle, &compiled_filter_expression, filter, 0, net) == -1)
    {
        cerr << "Filter parsing failed" << endl;
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &compiled_filter_expression) == -1)
    {
        cerr << "Filter application failed" << endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

string get_packet_payload(const u_char *packet_data, int packet_length)
{
    int packet_header_length = ICMP_HEADER_LENGTH + IPV4_HEADER_LENGTH + ETHERNET_HEADER_LENGTH;
    return string(packet_data + packet_header_length, packet_data + packet_length);
}

int process_packets(pcap_t *handle)
{
    const u_char *packet_raw;
    struct pcap_pkthdr packet_header;
    string packet_payload;
    // wait for start packet
    do
    {
        packet_raw = pcap_next(handle, &packet_header);
        packet_payload = get_packet_payload(packet_raw, packet_header.len);
    } while (packet_payload.find("Start\n") == string::npos);

    // open output file stream
    ofstream dest_file(packet_payload.substr(6), ios::out); // skip Start\n
    // write to file until end packet arrives
    for (;;)
    {
        packet_raw = pcap_next(handle, &packet_header);
        packet_payload = get_packet_payload(packet_raw, packet_header.len);
        if (packet_payload != "End")
        {
            dest_file << packet_payload;
        }
        else
        {
            break;
        }
    }
    // close file and pcap device
    dest_file.close();
    return EXIT_SUCCESS;
}

int recieve_file(char *interface)
{
    char error_buffer[PCAP_ERRBUF_SIZE];

    // open device for sniffing
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 0, 1000, error_buffer);
    if (handle == NULL)
    {
        cerr << "Couldn't open device" << interface << ":" << error_buffer << endl;
        return EXIT_FAILURE;
    }

    // set filter for ICMP packets
    if (set_pcap_filter(handle, interface, (char *)"icmp") != EXIT_SUCCESS)
    {
        cerr << "Couldn't set filter" << endl;
        return EXIT_FAILURE;
    }

    if (process_packets(handle) != EXIT_SUCCESS)
    {
        cerr << "Packet processing failed" << endl;
        return EXIT_FAILURE;
    }
    pcap_close(handle);
    return EXIT_SUCCESS;
}

sockaddr_in socket_address(string host)
{
    // TODO hostname to ip conversion
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &sin.sin_addr.s_addr);
    return sin;
}

int send_icmp_packet(char *data, int sequence_number, int socket_descriptor, int data_length, sockaddr *socket_address)
{

    char *icmp_packet = create_icmp_packet(data, data_length, ICMP_ECHO, sequence_number);
    if (sendto(socket_descriptor, icmp_packet, ICMP_HEADER_LENGTH + data_length, 0, socket_address, sizeof(struct sockaddr)) <= 0)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int send_file_via_icmp(string host, string filename)
{

    sockaddr_in sin = socket_address(host);
    int packet_number = 0;

    ifstream source_file(filename, ios::in);

    int socket_descriptor;
    if ((socket_descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        return EXIT_FAILURE;
    }
    // 6 = length of Start\n
    if (send_icmp_packet((char *)(string("Start\n") + filename).c_str(), packet_number++, socket_descriptor, filename.length() + 6, (struct sockaddr *)&sin) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }

    vector<char> buffer(1000);
    while (!source_file.eof())
    {
        source_file.read(buffer.data(), buffer.size());
        streamsize bytes_read = source_file.gcount();
        if (send_icmp_packet(buffer.data(), packet_number++, socket_descriptor, bytes_read, (struct sockaddr *)&sin) != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }

    if (send_icmp_packet((char *)"End", packet_number++, socket_descriptor, 3, (struct sockaddr *)&sin) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }

    close(socket_descriptor);
    source_file.close();
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
    // arguments parsing using getopt (-r <file> -s <ip|hostname> [-l])
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
    // mozna nepovinne?
    //  if (file_arg == "" || host == "")
    //  {
    //      cerr << "-s and -r options are required" << endl;
    //      return EXIT_FAILURE;
    //  }

    if (listen_mode) // server
    {

        char *default_interface = get_default_interface();
        if (default_interface == "")
        {
            return EXIT_FAILURE;
        }
        if (recieve_file(default_interface) != EXIT_SUCCESS)
        {

            return EXIT_FAILURE;
        }
    }

    else // client
    {
        if (send_file_via_icmp(host, file_arg) != EXIT_SUCCESS)
        {
            cerr << "Sending packet via icmp failed" << endl;
            return EXIT_FAILURE;
        }
    }

    return 0;
}