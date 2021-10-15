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

using namespace std;

#define ICMP_HEADER_LENGTH 8

uint8_t *create_icmp_packet(char *data, int data_length, int icmp_packet_type, int packet_seq_num)
{
    // icmp header
    struct icmp icmp_header;
    icmp_header.icmp_type = icmp_packet_type;
    icmp_header.icmp_code = 0;
    icmp_header.icmp_id = htons(99);
    icmp_header.icmp_seq = htons(packet_seq_num);
    icmp_header.icmp_cksum = 0;

    // allocate memory for packet (header + data)
    uint8_t *packet = new uint8_t[ICMP_HEADER_LENGTH + data_length];
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
    // if (file_arg == "" || host == "")
    // {
    //     cerr << "-s and -r options are required" << endl;
    //     return EXIT_FAILURE;
    // }
    if (listen_mode) // server
    {

        pcap_if_t *interfaces;
        char filter[] = "icmp";
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&interfaces, errbuf) == -1)
        {
            cerr << "error in pcap findall devs" << endl;
            return EXIT_FAILURE;
        }
        char *default_device = interfaces->name; // get first interface (default)

        pcap_t *handle;
        bpf_u_int32 mask; /* The netmask of our sniffing device */
        bpf_u_int32 net;  /* The IP of our sniffing device */
        if (pcap_lookupnet(default_device, &net, &mask, errbuf) < 0)
        {
            printf("pcap_lookupnet: %s\n", errbuf);
            return EXIT_FAILURE;
        }

        handle = pcap_open_live(default_device, BUFSIZ, 0, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", default_device, errbuf);
            return EXIT_FAILURE;
        }
        struct bpf_program compiled_filter_expression;
        if (pcap_compile(handle, &compiled_filter_expression, filter, 0, net) == -1)
        {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
            return EXIT_FAILURE;
        }
        if (pcap_setfilter(handle, &compiled_filter_expression) == -1)
        {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        struct pcap_pkthdr header;
        const u_char *packet;
        string packet_data;

        do
        {
            packet = pcap_next(handle, &header);
            packet_data = string((char *)&packet[42]);
        } while (packet_data != "Start transmission");

        // TODO vytahnout data o odesilateli asi

        packet = pcap_next(handle, &header);
        // string recieved_file_name = string((char*)&packet[42]);
        string recieved_file_name = "testovaci.txt";
        ofstream dest_file(recieved_file_name, ios::out);

        for(;;)
        {
            packet_data = "";
            packet = NULL;
            packet = pcap_next(handle, &header);
            char* addr = (char*)packet;
            addr[header.len] = '\0';
            packet_data = string((char *)&packet[42]);
            if(packet_data != "End")
            {
            dest_file << packet_data;
            }
            else
            {
                break;
            }
        }
        dest_file.flush();
        dest_file.close();

        /* And close the session */
        pcap_close(handle);
    }

    else // client
    {
        int packet_number = 0;
        ifstream source_file(file_arg, ios::in);
        vector<char> buffer(1000);

        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(struct sockaddr_in));
        sin.sin_family = AF_INET;

        int status;
        if (inet_pton(AF_INET, host.c_str(), &sin.sin_addr.s_addr) != 1)
        {
            cerr << "can't convert ip to in_addr format" << endl;
            return EXIT_FAILURE;
        }

        int socket_descriptor;
        if ((socket_descriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        {
            cerr << "Failed to open socket" << endl;
            return EXIT_FAILURE;
        }
        uint8_t *start_transmission_packet = create_icmp_packet((char *)"Start transmission", 18, ICMP_ECHO, packet_number++);
        if (sendto(socket_descriptor, start_transmission_packet, ICMP_HEADER_LENGTH + 18, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) <= 0)
        {
            cerr << "Failed sending packet" << endl;
            return EXIT_FAILURE;
        }

        uint8_t *file_name_packet = create_icmp_packet((char *)file_arg.c_str(), file_arg.length(), ICMP_ECHO, packet_number++);
        if (sendto(socket_descriptor, file_name_packet, ICMP_HEADER_LENGTH + file_arg.length(), 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) <= 0)
        {
            cerr << "Failed sending packet" << endl;
            return EXIT_FAILURE;
        }

        while (!source_file.eof())
        {
            source_file.read(buffer.data(), buffer.size());
            streamsize bytes_read = source_file.gcount();

            // vector<char> buffer_encrypted = encrypt_data(buffer);

            // vector<char> buffer_decrypted = decrypt_data(buffer_encrypted);

            uint8_t *icmp_echo_packet = create_icmp_packet(buffer.data(), bytes_read, ICMP_ECHO, packet_number++); // TODO change to encrypted buffer

            // TODO send packet via socket

            if (sendto(socket_descriptor, icmp_echo_packet, ICMP_HEADER_LENGTH + bytes_read, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) <= 0)
            {
                cerr << "Failed sending packet" << endl;
                return EXIT_FAILURE;
            }

            delete icmp_echo_packet;
        }

        uint8_t *end_transmission_packet = create_icmp_packet((char *)"End", 3, ICMP_ECHO, packet_number++);
        if (sendto(socket_descriptor, end_transmission_packet, ICMP_HEADER_LENGTH + 3, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) <= 0)
        {
            cerr << "Failed sending packet" << endl;
            return EXIT_FAILURE;
        }

        close(socket_descriptor);
        source_file.close();
    }

    return 0;
}