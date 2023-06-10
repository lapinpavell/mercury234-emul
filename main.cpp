#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int opt;
    std::string jsonPath;
    std::string mode;
    int port = 8000;
    bool help = false;

    while((opt = getopt(argc, argv, "j:m:p:h")) != -1)  
    {  
        switch(opt)  
        {  
            case 'j':  
                jsonPath = optarg;
                break;  
            case 'm':  
                mode = optarg;
                break;
            case 'p':
                port = std::stoi(optarg);
                break;  
            case 'h':  
                help = true;
                break;  
            case ':':  
                std::cout << "option needs a value" << std::endl;  
                break;  
            case '?':  
                std::cout << "unknown option: " << optopt << std::endl; 
                break;  
        }  
    }  

    if(help) {
        std::cout << "Usage: ./program -p <path_to_json> -m <mode> -t <tcp_port> [-h]" << std::endl;
        std::cout << "-j: Path to the JSON file" << std::endl;
        std::cout << "-m: Mode" << std::endl;
        std::cout << "-p: TCP port to open" << std::endl;
        std::cout << "-h: Display this help message" << std::endl;
    } else {
        std::cout << "Path to JSON: " << jsonPath << std::endl;
        std::cout << "Mode: " << mode << std::endl;
        std::cout << "TCP Port: " << port << std::endl;

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd < 0) {
            std::cerr << "Error opening socket" << std::endl;
            return 1;
        }

        sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        serv_addr.sin_addr.s_addr = INADDR_ANY;

        if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
            std::cerr << "Error binding socket" << std::endl;
            return 1;
        }

        listen(sockfd, 5);

        std::cout << "Listening on port " << port << std::endl;

        sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);

        int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if(newsockfd < 0) {
            std::cerr << "Error accepting connection" << std::endl;
            return 1;
        }

        std::cout << "Accepted a connection" << std::endl;
    }

    return 0;
}
