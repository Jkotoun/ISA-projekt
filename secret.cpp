#include <iostream>
#include <getopt.h>
#include <string>

int main(int argc, char *argv[]) {
    //arguments parsing using getopt (-r <file> -s <ip|hostname> [-l])
    int current_arg;
    std::string file = "";
    std::string host = "";
    bool listen_mode = false; 
    while((current_arg = getopt(argc, argv, "r:s:l")) != -1)
    {
        switch(current_arg)
        {
            case 'r':
            {
                file = optarg;
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
    if(file == "" || host == "")
    {
        std::cerr<<"-s and -r options are required"<<std::endl;
        exit(1);
    }

    if ()

    return 0;
    }