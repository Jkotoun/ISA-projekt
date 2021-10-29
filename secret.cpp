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
#include <netinet/if_ether.h>
#include <netinet/ip6.h>


#define ICMP_HEADER_LENGTH 8
#define IPV4_HEADER_LENGTH 20
#define IPV6_HEADER_LENGTH 40
#define ETHERNET_HEADER_LENGTH 14

//returns pointer to icmp packet (header + data)
char *create_icmp_packet(char *data, int packet_sequence_number, int data_length, sa_family_t ipfamily)
{
    // allocate memory for packet (header + data)
    char *packet = new char[ICMP_HEADER_LENGTH + data_length];
    struct icmp icmp_header;
    icmp_header.icmp_cksum = 0;
    icmp_header.icmp_seq = packet_sequence_number;
    if (ipfamily == AF_INET) // ipv4
    {
        icmp_header.icmp_code = ICMP_ECHO;
        icmp_header.icmp_type = ICMP_ECHO;
    }
    else
    {
        icmp_header.icmp_code = ICMP6_ECHO_REQUEST;
        icmp_header.icmp_type = ICMP6_ECHO_REQUEST;
    }
    std::memcpy(packet, &icmp_header, sizeof(struct icmphdr));
    std::memcpy(packet + sizeof(struct icmphdr), data, data_length);
    return packet;
}
//encrypt data with AES cipher 
std::vector<char> encrypt_data(std::vector<char> data, int data_bytes)
{
    std::vector<char> encrypted_buffer(data_bytes);
    int padding_count = ((16 - data.size() % 16) % 16);
    if (padding_count != 0)
    {
        padding_count += 16; // minimum of 16 bytes padding to minimize chance of wrong padding interpretation
        data.resize(data.size() + padding_count - 1, 0);
        data.push_back(padding_count);
        encrypted_buffer.resize(encrypted_buffer.size() + padding_count, 0);
    }
    AES_KEY aes_key;
    if (AES_set_encrypt_key((unsigned char *)"xkotou06", 128, &aes_key) != 0)
    {
        exit(EXIT_FAILURE); // error handling
    }
    int i = 0;
    while (i < data.size())
    {

        AES_encrypt((unsigned char *)&data.data()[i], (unsigned char *)&encrypted_buffer.data()[i], &aes_key);
        i += 16;
    }
    return encrypted_buffer;
}
//decrypt data with AES cipher
std::vector<char> decrypt_data(std::vector<char> data, int data_size)
{
    std::vector<char> decrypted_buffer(data_size, 0);
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
    bool padding = true;
    int padding_size = (int)decrypted_buffer.data()[data_size - 1]; // last number is count of padding bytes
    for (int i = data_size - padding_size; i < data_size - 1; i++)
    {
        if (decrypted_buffer[i] != 0)
        {
            padding = false;
            break;
        }
    }
    if (padding)
    {
        for (int i = 0; i < padding_size; i++)
        {
            decrypted_buffer.pop_back();
        }
    }
    return decrypted_buffer;
}

// returns default interface - should be first in interfaces list
char *get_default_interface()
{
    pcap_if_t *interfaces;
    char error_buffer[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&interfaces, error_buffer) == -1)
    {
        std::cerr << error_buffer << std::endl;
        return (char *)"";
    }
    return interfaces->name; // get first interface (default)
}

//sets filter for pcap device
int set_pcap_filter(pcap_t *handle, char *interface, char *filter)
{
    // net and mask of device
    bpf_u_int32 mask;
    bpf_u_int32 net;
    char error_buffer[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(interface, &net, &mask, error_buffer) < 0)
    {
        std::cerr << error_buffer << std::endl;
        return EXIT_FAILURE;
    }
    struct bpf_program compiled_filter_expression;
    if (pcap_compile(handle, &compiled_filter_expression, filter, 0, net) == -1)
    {
        std::cerr << "Filter parsing failed" << std::endl;
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &compiled_filter_expression) == -1)
    {
        std::cerr << "Filter application failed" << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

//extract data from packet
std::string get_packet_payload(const u_char *packet_data, int packet_length, uint16_t eth_type)
{
    int packet_header_length = 0;
    if (eth_type == ETHERTYPE_IP) // ipv4
    {
        packet_header_length = ICMP_HEADER_LENGTH + IPV4_HEADER_LENGTH + ETHERNET_HEADER_LENGTH;
    }
    else if (eth_type == ETHERTYPE_IPV6)
    {
        packet_header_length = ICMP_HEADER_LENGTH + IPV6_HEADER_LENGTH + ETHERNET_HEADER_LENGTH;
    }
    return std::string(packet_data + packet_header_length, packet_data + packet_length);
}

//sniff ICMP packets, decrypt its data and write to file
int process_packets(pcap_t *handle, char *interface)
{
    const u_char *packet_raw;
    struct pcap_pkthdr packet_header;
    std::string packet_payload;
    std::string packet_payload_decrypted;
    std::vector<char> decrypted_vector;
    uint16_t eth_type;
    // wait for start packet
    do
    {
        packet_raw = pcap_next(handle, &packet_header);
        struct ether_header *eptr;
        eptr = (struct ether_header *)packet_raw;
        eth_type = ntohs(eptr->ether_type);

        packet_payload = get_packet_payload(packet_raw, packet_header.len, eth_type);
        decrypted_vector = decrypt_data(std::vector<char>(packet_payload.begin(), packet_payload.end()), packet_payload.length());
        packet_payload_decrypted = std::string(decrypted_vector.begin(), decrypted_vector.end());
    } while (packet_payload_decrypted.find("Start\n") == std::string::npos);
    char src_ip[100];
    if (eth_type == ETHERTYPE_IP) // ipv4
    {
        inet_ntop(AF_INET, &((struct ip *)(packet_raw + ETHERNET_HEADER_LENGTH))->ip_src, src_ip, 100);
    }
    else if (eth_type == ETHERTYPE_IPV6)
    {
        inet_ntop(AF_INET6, &((struct ip6_hdr *)(packet_raw + ETHERNET_HEADER_LENGTH))->ip6_src, src_ip, 100);
    }
    // process only icmp packets from sender
    std::string filter = "(icmp or icmp6) and src " + std::string(src_ip);
    if (set_pcap_filter(handle, interface, (char *)filter.c_str()) != EXIT_SUCCESS)
    {
        std::cerr << "Couldn't set filter" << std::endl;
        return EXIT_FAILURE;
    }
    std::ofstream dest_file(packet_payload_decrypted.substr(6), std::ios::out);
    for (;;)
    {
        packet_raw = pcap_next(handle, &packet_header);
        packet_payload = get_packet_payload(packet_raw, packet_header.len, eth_type);
        decrypted_vector = decrypt_data(std::vector<char>(packet_payload.begin(), packet_payload.end()), packet_payload.length());
        packet_payload_decrypted = std::string(decrypted_vector.begin(), decrypted_vector.end());
        if (packet_payload_decrypted.substr(0, 3) != "End") // remove decode padding to 16 bytes in end packet
        {
            dest_file << packet_payload_decrypted;
        }
        else
        {
            break;
        }
    }
    dest_file.close();
    return EXIT_SUCCESS;
}

//saves icmp packets data to file using custom protocol
int recieve_file(char *interface)
{
    char error_buffer[PCAP_ERRBUF_SIZE];

    // open device for sniffing
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 0, 1000, error_buffer);
    if (handle == NULL)
    {
        std::cerr << "Couldn't open device" << interface << ":" << error_buffer << std::endl;
        return EXIT_FAILURE;
    }

    // set filter for ICMP packets
    if (set_pcap_filter(handle, interface, (char *)"icmp or icmp6") != EXIT_SUCCESS)
    {
        std::cerr << "Couldn't set filter" << std::endl;
        return EXIT_FAILURE;
    }

    if (process_packets(handle, interface) != EXIT_SUCCESS)
    {
        std::cerr << "Packet processing failed" << std::endl;
        return EXIT_FAILURE;
    }
    pcap_close(handle);
    return EXIT_SUCCESS;
}
//create icmp packet and send it by given socket
int send_icmp_packet(char *data, int socket_descriptor, int data_length, int packet_sequence_number, addrinfo *servinfo)
{
    char *icmp_packet = create_icmp_packet(data, packet_sequence_number, data_length, servinfo->ai_family);

    if (sendto(socket_descriptor, icmp_packet, ICMP_HEADER_LENGTH + data_length, 0, (struct sockaddr *)(servinfo->ai_addr), servinfo->ai_addrlen) <= 0)
    {
        return EXIT_FAILURE;
    }
    delete icmp_packet;
    return EXIT_SUCCESS;
}
//split file to packets and send to server given by server_info
int send_file_via_icmp(addrinfo *server_info, std::string filename)
{
    std::ifstream source_file(filename, std::ios::in);
    if(!source_file.good())
    {
        return EXIT_FAILURE;
    }
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
    std::string start_str = std::string("Start\n") + filename;
    std::vector<char> start_message(start_str.begin(), start_str.end());
    std::vector<char> encrypted_start_message = encrypt_data(start_message, start_message.size());

    // 6 = length of Start\n
    int packet_sequence_number = 0;
    if (send_icmp_packet(encrypted_start_message.data(), socket_descriptor, encrypted_start_message.size(), packet_sequence_number++, server_info) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }
    std::vector<char> buffer(1400);

    while (!source_file.eof())
    {
        buffer.clear();
        buffer.resize(1400);
        source_file.read(buffer.data(), buffer.size());
        std::streamsize bytes_read = source_file.gcount();
        buffer.resize(bytes_read);
        std::vector<char> buffer_encrypted = encrypt_data(buffer, bytes_read);
        usleep(1000);
        if (send_icmp_packet(buffer_encrypted.data(), socket_descriptor, buffer_encrypted.size(), packet_sequence_number++, server_info) != EXIT_SUCCESS)
        {
            return EXIT_FAILURE;
        }
    }
    std::vector<char> end_message = {'E', 'n', 'd'};
    std::vector<char> encrypted_end_message = encrypt_data(end_message, 3);
    if (send_icmp_packet(encrypted_end_message.data(), socket_descriptor, encrypted_end_message.size(), packet_sequence_number++, server_info) != EXIT_SUCCESS)
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
    std::string file_arg = "";
    std::string host = "";
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
     if ((file_arg == "" || host == "") && !listen_mode)
     {
         std::cerr << "-s and -r arguments are required in client mode" << std::endl;
         return EXIT_FAILURE;
     }
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
            std::cerr << "Failed getting address info" << std::endl;
            return EXIT_FAILURE;
        }

        if (send_file_via_icmp(server_info, file_arg) != EXIT_SUCCESS)
        {
            std::cerr << "Sending packet via icmp failed" << std::endl;
            return EXIT_FAILURE;
        }
    }

    return 0;
}