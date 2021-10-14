#include <iostream>
#include <getopt.h>
#include <string>
#include <fstream>
#include <vector>
#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <cstring>
#include <openssl/aes.h>
using namespace std;

#define ICMP_HEADER_LENGTH 8

uint8_t *create_icmp_packet(char *data, int data_length, int icmp_packet_type, int packet_seq_num)
{
    // icmp header
    struct icmp icmp_header;
    icmp_header.icmp_type =  icmp_packet_type;
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
    if (AES_set_encrypt_key((unsigned char *)"xkotou06", 256, &aes_key) != 0)
    {
        exit(EXIT_FAILURE); //error handling
    }
    AES_encrypt((unsigned char *)data.data(), (unsigned char *)encrypted_buffer.data(), &aes_key);
    return encrypted_buffer;
}

vector<char> decrypt_data(vector<char> data)
{
    vector<char> decrypted_buffer(1000);
    AES_KEY aes_key;
    if (AES_set_decrypt_key((unsigned char *)"xkotou06", 256, &aes_key) != 0)
    {
        exit(EXIT_FAILURE); //error handling
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
    if (file_arg == "" || host == "")
    {
        cerr << "-s and -r options are required" << endl;
        return EXIT_FAILURE;
    }
    if (listen_mode) // server
    {
    }
    else // client
    {
        int packet_number = 0;
        ifstream source_file(file_arg, ios::in);
        vector<char> buffer(1000);
        

        while (!source_file.eof())
        {
            source_file.read(buffer.data(), buffer.size());
            streamsize bytes_read = source_file.gcount();
            
            vector<char> buffer_encrypted = encrypt_data(buffer);
            uint8_t *icmp_echo_packet = create_icmp_packet(buffer_encrypted.data(), bytes_read, ICMP_ECHO, packet_number++);

            // TODO send packet via socket
       
            delete icmp_echo_packet;
        }

        source_file.close();
    }

    return 0;
}