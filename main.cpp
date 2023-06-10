#include <iostream>
#include <cstdint>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

// Расчёт CRC16 с полиномом MODBUS
uint16_t crc16(uint8_t* data, size_t length) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint16_t)data[i];
        for (int j = 8; j != 0; j--) {
            if ((crc & 0x0001) != 0) {
                crc >>= 1;
                crc ^= 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}


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

        uint8_t buffer[1024] = {0}; // буфер приёма
        uint8_t message[4] = {0x80, 0x00, 0x00, 0x00}; // запрос на тестирование канала связи
        uint8_t response[4] = {0x80, 0x00, 0x00, 0x00}; // ответ на запрос

        // Расчёт CRC запроса
        uint16_t crc = crc16(message, 2);
        uint8_t crc_high = crc >> 8;
        uint8_t crc_low = crc & 0xFF;

        std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;

        // FIXME: почему-то перепутан порядок байт
        message[2] = crc_low;
        message[3] = crc_high;

        // Чтение запроса
        read(newsockfd, buffer, 4);

        std::cout << "Message: ";
        for (int i = 0; i < 4; i++) {
           std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
        }
        std::cout << std::endl;

        // Проверка соостветствия запроса
        if (memcmp(buffer, message, 4) == 0) {

            // Расчёт CRC ответа
            crc = crc16(response, 2);
            crc_high = crc >> 8;
            crc_low = crc & 0xFF;

            // FIXME: почему-то перепутан порядок байт
            response[2] = crc_low;
            response[3] = crc_high;

            // Отправка ответа
            send(newsockfd, response, 4, 0);
            printf("Response sent\n");
        } else {
            printf("Received message does not match the specified byte sequence\n");
        }

/*
        uint8_t buffer[1024] = {0}; // буфер приёма
        uint8_t message[11] = {0x80, 0x01, 0x01, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x00, 0x00}; // запрос на открытие канала связи
        uint8_t response[4] = {0x80, 0x00, 0x00, 0x00}; // ответ на запрос

        read(newsockfd, buffer, 11);

        // Проверка соостветствия запроса
        if (memcmp(buffer, message, 11) == 0) {

            // Расчёт CRC ответа
            uint16_t crc = calculateCRC(response, 2);
            response[2] = crc >> 8;
            response[3] = crc & 0xFF;

            // Отправка ответа
            send(newsockfd, response, 4, 0);
            printf("Response sent\n");
        } else {
            printf("Received message does not match the specified byte sequence\n");
        }
*/

    }

    return 0;
}
