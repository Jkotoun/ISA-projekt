#include <iostream>
#include <getopt.h>
#include <string>
#include <fstream>
#include <vector>
#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
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
// TODO ipv6

char *create_icmp_packet(char *data, int data_length, sa_family_t ipfamily)
{
    // allocate memory for packet (header + data)
    char *packet = new char[ICMP_HEADER_LENGTH + data_length];
    if (ipfamily == AF_INET) // ipv4
    {
        struct icmp icmp_header;
        icmp_header.icmp_code = ICMP_ECHO;
        icmp_header.icmp_type = ICMP_ECHO;
        icmp_header.icmp_cksum = 0;
        std::memcpy(packet, &icmp_header, ICMP_HEADER_LENGTH);
        std::memcpy(packet + ICMP_HEADER_LENGTH, data, data_length);
    }
    // else
    // {

    //     struct icmp6_hdr icmp_header;
    //     icmp_header.icmp6_cksum = 0;
    //     icmp_header.icmp6_code = ICMP6_ECHO_REQUEST;
    //     icmp_header.icmp6_type = ICMP6_ECHO_REQUEST;
    //     std::memcpy(packet, &icmp_header, 4);
    //     std::memcpy(packet + 4, data, data_length);
    // }

    // copy header and data to allocated memory

    return packet;
}

vector<char> encrypt_data(vector<char> data, int data_bytes)
{

    vector<char> encrypted_buffer(data_bytes);
    data.resize(data.size() + (16 - data.size() % 16) % 16, 0);
    encrypted_buffer.resize(encrypted_buffer.size() + (16 - encrypted_buffer.size() % 16) % 16, 0);
    AES_KEY aes_key;
    if (AES_set_encrypt_key((unsigned char *)"xkotou06", 128, &aes_key) != 0)
    {
        exit(EXIT_FAILURE); // error handling
    }
    int i = 0;
    while (i < data_bytes)
    {

        AES_encrypt((unsigned char *)&data.data()[i], (unsigned char *)&encrypted_buffer.data()[i], &aes_key);
        i += 16;
    }
    return encrypted_buffer;
}

vector<char> decrypt_data(vector<char> data, int data_size)
{
    vector<char> decrypted_buffer(data_size, 0);
    AES_KEY aes_key;
    if (AES_set_decrypt_key((unsigned char *)"xkotou06", 128, &aes_key) != 0)
    {
        exit(EXIT_FAILURE); // error handling
    }
    int i = 0;
    while (i < data_size)
    {
        AES_decrypt((unsigned char *)&data.data()[i], (unsigned char *)&decrypted_buffer.data()[i], &aes_key);
        i += 16;
    }
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

int process_packets(pcap_t *handle, char *interface)
{
    const u_char *packet_raw;
    struct pcap_pkthdr packet_header;
    string packet_payload;
    string packet_payload_decrypted;

    // wait for start packet
    do
    {
        packet_raw = pcap_next(handle, &packet_header);
        packet_payload = get_packet_payload(packet_raw, packet_header.len);
        packet_payload_decrypted = string(decrypt_data(vector<char>(packet_payload.begin(), packet_payload.end()), packet_payload.length()).data());
    } while (packet_payload_decrypted.find("Start\n") == string::npos);

    char *src_ip = inet_ntoa(((struct ip *)(packet_raw + ETHERNET_HEADER_LENGTH))->ip_src);

    // process only icmp packets from sender
    string filter = "src " + string(src_ip);
    if (set_pcap_filter(handle, interface, (char *)filter.c_str()) != EXIT_SUCCESS)
    {
        cerr << "Couldn't set filter" << endl;
        return EXIT_FAILURE;
    }
    // open output file stream
    ofstream dest_file(packet_payload_decrypted.substr(6), ios::out); // skip Start\n
    // write to file until end packet arrives
    for (;;)
    {
        packet_raw = pcap_next(handle, &packet_header);
        packet_payload = get_packet_payload(packet_raw, packet_header.len);
        string packet_payload_decrypted = string(decrypt_data(vector<char>(packet_payload.begin(), packet_payload.end()), packet_payload.length()).data());
        if (packet_payload_decrypted != "End")
        {
            dest_file << packet_payload_decrypted;
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
    if (set_pcap_filter(handle, interface, (char *)"icmp or icmp6") != EXIT_SUCCESS)
    {
        cerr << "Couldn't set filter" << endl;
        return EXIT_FAILURE;
    }

    if (process_packets(handle, interface) != EXIT_SUCCESS)
    {
        cerr << "Packet processing failed" << endl;
        return EXIT_FAILURE;
    }
    pcap_close(handle);
    return EXIT_SUCCESS;
}

int send_icmp_packet(char *data, int socket_descriptor, int data_length, sockaddr *socket_address)
{
    char *icmp_packet = create_icmp_packet(data, data_length, socket_address->sa_family);
    if (sendto(socket_descriptor, icmp_packet, ICMP_HEADER_LENGTH + data_length, 0, socket_address, sizeof(struct sockaddr)) <= 0)
    {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int send_file_via_icmp(addrinfo *server_info, string filename)
{
    ifstream source_file(filename, ios::in);
    int socket_descriptor;
    int type;
    if (server_info->ai_family == AF_INET)
    {
        type = IPPROTO_ICMP;
    }
    else
    {
        type = IPPROTO_ICMPV6;
    }
    if ((socket_descriptor = socket(server_info->ai_family, server_info->ai_socktype, type)) < 0)
    {
        return EXIT_FAILURE;
    }

    string start_str = string("Start\n") + filename;
    vector<char> start_message(start_str.begin(), start_str.end());
    vector<char> encrypted_start_message = encrypt_data(start_message, start_message.size());

    // 6 = length of Start\n
    if (send_icmp_packet(encrypted_start_message.data(), socket_descriptor, encrypted_start_message.size(), server_info->ai_addr) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }
    vector<char> buffer(1400);
    while (!source_file.eof())
    {
        buffer.clear();
        buffer.resize(1400);
        source_file.read(buffer.data(), buffer.size());
        buffer.shrink_to_fit();
        streamsize bytes_read = source_file.gcount();
        vector<char> buffer_encrypted = encrypt_data(buffer, bytes_read);
        if (send_icmp_packet(buffer_encrypted.data(), socket_descriptor, buffer_encrypted.size(), server_info->ai_addr) != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }
    vector<char> end_message = {'E', 'n', 'd'};
    vector<char> encrypted_end_message = encrypt_data(end_message, 3);
    if (send_icmp_packet(encrypted_end_message.data(), socket_descriptor, encrypted_end_message.size(), server_info->ai_addr) != EXIT_SUCCESS)
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
        while (true)
        {
            if (recieve_file(default_interface) != EXIT_SUCCESS)
            {
                return EXIT_FAILURE;
            }
        }
    }
    else // client
    {
        struct addrinfo hints, *server_info;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_RAW;
        if (getaddrinfo(host.c_str(), NULL, &hints, &server_info) != 0)
        {
            cerr << "Failed getting address info" << endl;
            return EXIT_FAILURE;
        }

        if (send_file_via_icmp(server_info, file_arg) != EXIT_SUCCESS)
        {
            cerr << "Sending packet via icmp failed" << endl;
            return EXIT_FAILURE;
        }
    }

    return 0;
}