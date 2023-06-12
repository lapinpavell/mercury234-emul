#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

#define MAX_CLIENTS 4
#define MAX_REQUEST_LEN 19
#define MIN_REQUEST_LEN 4
#define MAX_RESPONSE_LEN 1024
#define MIN_RESPONSE_LEN 4
#define BUFFER_SIZE 1024
#define SOCKET_CREATION_FAILED -1
#define SOCKET_BINDING_FAILED -2
#define SOCKET_LISTEN_FAILED -3

template <typename T>
void print_message(const T* arr, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(arr[i]) << ' ';
    }
    std::cout << '\n';
}

// Расчёт CRC16 с полиномом MODBUS
uint16_t crc16(const uint8_t* data, size_t length) {
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

// Параметры из json-файла
class Parameter {
public:
    uint8_t parameter_number;
    std::string name;
    std::vector<uint8_t> device_response;
    std::string device_response_description;

    Parameter(uint8_t parameter_number, 
              const std::string& name, 
              const std::vector<uint8_t>& device_response,
              const std::string& device_response_description)
        : parameter_number(parameter_number),
          name(name),
          device_response(device_response),
          device_response_description(device_response_description) {}
};

std::vector<Parameter> all_parameters;

// Обработка запросов
class RequestHandler {
public:
    void handle(uint8_t* request, size_t request_length, uint8_t* response, size_t& response_length) {

        // Проверка длины запроса
        if (request_length < MIN_REQUEST_LEN || request_length > MAX_REQUEST_LEN) {
            std::cerr << "Invalid request size" << std::endl;
            return;
        }

        // 1 байт - сетевой адрес, 2-17 тело запроса, последние 2 байта - crc16
        uint8_t address = request[0];
        size_t body_length = request_length - 3;
        uint8_t request_body[MAX_REQUEST_LEN - 2] = {0};
        std::copy(request + 1, request + 1 + body_length, request_body);

        // Валидация crc запроса
        uint16_t crc = (request[request_length - 1] << 8) | request[request_length - 2];
        if (!validate_crc16(request, request_length, crc)) {
            std::cerr << "CRC16 validation failed" << std::endl;
            return;
        }

        // Генерация ответа
        uint8_t response_body[MAX_RESPONSE_LEN - 2] = {0};
        response_length = process_request(address, request_body, body_length, response_body) + 2;

        // Добавление crc16 к ответу
        uint16_t response_crc = calculate_crc16(response_body, response_length - 2);
        response_body[response_length - 2] = response_crc & 0x00FF;
        response_body[response_length - 1] = response_crc >> 8;

        std::copy(response_body, response_body + response_length, response);
    }

private:
    // Валидация crc16
    bool validate_crc16(const uint8_t* data, size_t size, uint16_t crc) {
        uint16_t crc_byte = crc16(data, size - 2);
        uint8_t crc_high = crc_byte >> 8;
        uint8_t crc_low = crc_byte & 0x00FF;

        if (((crc >> 8) != crc_high) || ((crc & 0x00FF) != crc_low)) {
            return false;
        }

        return true;
    }

    // Расчёт crc16
    uint16_t calculate_crc16(const uint8_t* data, size_t size) {
        uint16_t crc = crc16(data, size);
        return crc;
    }

    // TODO: сделать возврат стандартной ошибки по умолчанию
    // TODO: сделать все ответы загружаемыми из json-файла
    size_t process_request(uint8_t address, uint8_t* request_body, size_t body_length, uint8_t* response_body) {
        size_t response_length = 0;
        response_body[0] = address;

        switch (request_body[0]) {
            default: break;
            
            // Тестирование канала связи
            case 0x00:
                response_body[1] = 0x00;
                response_length = 2;
                break;
            
            // Открытие канала связи
            // TODO: уровни доступа
            case 0x01:
                response_body[1] = 0x00;
                response_length = 2;
                break;
            
            // Закрытие канала связи
            case 0x02:
                response_body[1] = 0x00;
                response_length = 2;
                break;

            // Чтение параметров
            case 0x08:
                 switch (request_body[1]) {
                    default: break;

                    // Серийный номер и дата выпуска
                    case 0x00:
                        response_body[1] = 0x29;
                        response_body[2] = 0x5A;
                        response_body[3] = 0x40;
                        response_body[4] = 0x43;
                        response_body[5] = 0x16;
                        response_body[6] = 0x06;
                        response_body[7] = 0x14;
                        response_length = 8;
                        break;

                    // Версия ПО счётчика
                    case 0x03:
                        response_body[1] = 0x09;
                        response_body[2] = 0x00;
                        response_body[3] = 0x00;
                        response_length = 4;
                        break;
                    
                    // Вариант исполнения
                    case 0x12:
                        response_body[1] = 0xB4;
                        response_body[2] = 0xE3;
                        response_body[3] = 0xC2;
                        response_body[4] = 0x97;
                        response_body[5] = 0xDF;
                        response_body[6] = 0x58;
                        response_length = 7;
                        break;
                    
                    // Сетевой адрес
                    case 0x05:
                        response_body[1] = 0x00;
                        response_body[2] = 0x80;
                        response_length = 3;
                        break;
                    
                    // Расширенный перечень параметров прибора
                    case 0x01:
                        response_body[1] = 0x20;
                        response_body[2] = 0x57;
                        response_body[3] = 0x2F;
                        response_body[4] = 0x42;
                        response_body[5] = 0x1A;
                        response_body[6] = 0x06;
                        response_body[7] = 0x12;
                        response_body[8] = 0x09;
                        response_body[9] = 0x00;
                        response_body[10] = 0x00;
                        response_body[11] = 0xB4;
                        response_body[12] = 0xE3;
                        response_body[13] = 0xC2;
                        response_body[14] = 0x97;
                        response_body[15] = 0xDF;
                        response_body[16] = 0x58;
                        response_body[17] = 0x7E;
                        response_body[18] = 0xF5;
                        response_body[19] = 0x32;
                        response_body[20] = 0x3A;
                        response_body[21] = 0x0C;
                        response_body[22] = 0x00;
                        response_body[23] = 0x00;
                        response_body[24] = 0x00;
                        response_length = 25;
                        break;

                    // crc16 ПО счётчика
                    case 0x26:
                        response_body[1] = 0x7E;
                        response_body[2] = 0xF5;
                        response_length = 3;
                        break;
                    
                    // Коэффициент трансформации
                    case 0x02:
                        response_body[1] = 0x00;
                        response_body[2] = 0x01;
                        response_body[3] = 0x00;
                        response_body[4] = 0x01;
                        response_length = 5;
                        break;
                }
                break;
        }

        return response_length; // TODO: проверять размер
    }
};

// Энергия от сброса
bool get_current_state(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    // uint8_t message[6]  = {0x80, 0x05, 0x40, 0x00, 0x00, 0x00}; // запрос на чтение энегрии за текущие сутки
    uint8_t message[6]  = {0x80, 0x08, 0x14, 0xE0, 0x00, 0x00}; // запрос на чтение энегрии за текущие сутки
    // uint8_t response[19] = {0x80, 0x00, 0x00, 0x70, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // ответ на запрос
    uint8_t response[19] = {0x80, 0x00, 0x00, 0x6D, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF1, 0x00, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 4);

    uint8_t crc_high = crc >> 8;
    uint8_t crc_low  = crc & 0xFF;

    std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Get current state" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[4] = crc_low;
    message[5] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 5);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    }

    message[5] = 0x00; // FIXME: где-то обнуляется старший байт crc
    std::cout << "Message: ";
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::endl;

    // Проверка соостветствия запроса
    if (memcmp(buffer, message, 6) == 0) {

        // Расчёт CRC ответа
        crc = crc16(response, 17);
        crc_high = crc >> 8;
        crc_low = crc & 0xFF;

        // FIXME: почему-то перепутан порядок байт
        response[17] = crc_low;
        response[18] = crc_high;

        // Отправка ответа
        send(sockfd, response, 19, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 19; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}


// Старт сокета
int open_socket(int port) {
    int sockfd;
    struct sockaddr_in serv_addr;

    // Создание сокета
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Socket creation failed.\n";
        return SOCKET_CREATION_FAILED;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    // Подключение к порту
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Failed to bind socket to port " << port << ".\n";
        close(sockfd);
        return SOCKET_BINDING_FAILED;
    }
    
    // Слушать через сокет
    if (listen(sockfd, MAX_CLIENTS) < 0) {
        std::cerr << "Failed to listen on socket.\n";
        close(sockfd);
        return SOCKET_LISTEN_FAILED;
    }

    std::cout << "Server listening on port " << port << ".\n";
    return sockfd;
}

struct client_data {
    int socket;
    //
};

// Обработка клиентов
void* handle_client(void* arg) {
    RequestHandler handler;
    client_data* data = static_cast<client_data*>(arg);
    int newsockfd = data->socket;

    while (true) {
        uint8_t request[MAX_REQUEST_LEN];
        uint8_t response[MAX_RESPONSE_LEN];

        // Чтение запроса
        ssize_t request_length = read(newsockfd, request, sizeof(request));
        if (request_length < 0) {
            std::cerr << "Failed to read from socket.\n";
        } else if (request_length == 0) {
            std::cout << "Client disconnected.\n";
        }

        std::cout << "Request: ";
        print_message(request, request_length);

        // Подготовка ответа
        size_t response_length;
        handler.handle(request, request_length, response, response_length);

        std::cout << "Response: ";
        print_message(response, response_length);

        // Отправка ответа
        send(newsockfd, response, response_length, 0);
    }

    close(newsockfd);
    delete data;
    return nullptr;
}

// Приём подключений
bool accept_connections(int sockfd) {
    struct sockaddr_in cli_addr; // адрес клиента
    socklen_t clilen = sizeof(cli_addr);
    
    while (true) {
        int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) {
            std::cerr << "Error accepting new connection.\n";
            return false;
        }

        client_data* data = new client_data;
        data->socket = newsockfd;

        pthread_t thread;
        if (pthread_create(&thread, nullptr, handle_client, data) != 0) {
            std::cerr << "Failed to create thread.\n";
            return false;
        }

        pthread_detach(thread);
    }

    return true;
}

int main(int argc, char *argv[]) {
    int opt;
    std::string json_path;
    std::string mode;
    int port = 8000;
    bool help = false;

    while ((opt = getopt(argc, argv, "j:m:p:h")) != -1)  
    {  
        switch (opt)  
        {  
            case 'j':  
                json_path = optarg;
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

    if (help) {
        std::cout << "Usage: ./program -j <path_to_json> -m <mode> -p <tcp_port> [-h]" << std::endl;
        std::cout << "-j: Path to the JSON file" << std::endl;
        std::cout << "-m: Mode" << std::endl;
        std::cout << "-p: TCP port to open" << std::endl;
        std::cout << "-h: Display this help message" << std::endl;
    } else {
        std::cout << "Path to JSON: " << json_path << std::endl;
        std::cout << "Mode: " << mode << std::endl;
        std::cout << "TCP Port: " << port << std::endl;

        // Загрузка json-файла
        std::ifstream ifs(json_path);
        if (!ifs.is_open()) {
            std::cerr << "Failed to open JSON file\n";
            return 1;
        }

        json j;
        try {
            ifs >> j;
        }
        catch (json::parse_error& e) {
            std::cerr << "Failed to parse the JSON file: " << e.what() << '\n';
            return 1;
        }

        // Заполнение массива параметров
        json parameters = j["parameters"];
        for (const auto& parameter : parameters) {

            // Конвертация номера параметра из строки в байт (запрос)
            std::stringstream converter(parameter["parameter_number"].get<std::string>());
            unsigned int parameter_number_int;
            converter >> std::hex >> parameter_number_int;
            uint8_t parameter_number = static_cast<uint8_t>(parameter_number_int);

            // Наименование
            std::string name = parameter["name"];

            // Ответ
            std::string device_response_hex = parameter["device_response"];
            int device_response_len = device_response_hex.length() / 2;
            std::vector<uint8_t> device_response(device_response_len);
            for (int i = 0; i < device_response_len; i++) {
                std::stringstream converter(device_response_hex.substr(i * 2, 2));
                unsigned int byte;
                converter >> std::hex >> byte;
                device_response[i] = static_cast<uint8_t>(byte);
            }

            // Описание
            std::string device_response_description = parameter["device_response_description"];

            all_parameters.push_back(Parameter(parameter_number, name, device_response, device_response_description));
        }      

        // Обработка подключений
        int sockfd = open_socket(port);
        if (!accept_connections(sockfd)) {
            std::cerr << "Failed to accept connections.\n";
            return 1;
        }
    }

    return 0;
}
