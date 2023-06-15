#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <ctime>
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

// Флаги имитации задержек, потерь и искажений
bool enable_latency = false;
bool enable_packet_loss = false;
bool enable_distortion = false;

// Форматированный вывод сообщений
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

// Конвертация строки в байт
uint8_t hex_string_to_byte(const std::string& hex_string) {
    std::stringstream converter(hex_string);
    unsigned int code_int;
    converter >> std::hex >> code_int;
    uint8_t code = static_cast<uint8_t>(code_int);
    return code;
}

// Конвертация строки в массив
std::vector<uint8_t> hex_string_to_vector(const std::string& hex_string) {
    int response_length = hex_string.length() / 2;
    std::vector<uint8_t> response(response_length);

    for (int i = 0; i < response_length; i++) {
        std::stringstream converter(hex_string.substr(i * 2, 2));
        unsigned int byte;
        converter >> std::hex >> byte;
        response[i] = static_cast<uint8_t>(byte);
    }

    return response;
}

// Параметры из json-файла
class Parameter {
public:
    uint8_t code;
    std::string name;
    std::vector<uint8_t> device_response;
    std::string device_response_description;

    Parameter(uint8_t code, 
              const std::string& name, 
              const std::vector<uint8_t>& device_response,
              const std::string& device_response_description)
        : code(code),
          name(name),
          device_response(device_response),
          device_response_description(device_response_description) {}
};

// Показания из json-файла
class DataItem {
public:
    uint8_t array_code;
    std::vector<uint8_t> device_response;
    std::string array_description;

    DataItem(uint8_t array_code,
             std::vector<uint8_t> device_response,
             std::string array_description)
        : array_code(array_code),
          device_response(device_response),
          array_description(array_description) {}
};

class Data {
public:
    uint8_t code;
    std::vector<DataItem> array;

    Data(uint8_t code, std::vector<DataItem> array) : code(code), array(array) {}
};

// Массивы с параметрами и текущими показаниями
std::vector<Parameter> params;
// std::vector<DataItem> arrays;
std::vector<Data> datas;

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

        // Проверка длины ответа
        if (response_length <= 0) {
            std::cerr << "Response generation failed" << std::endl;
            return;
        }

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

    // Заполнение тела ответа на запрос параметров
    uint16_t fill_response_body(uint8_t code, uint8_t* response_body) {

        // Поиск по коду запроса
        for (const auto& parameter : params) {
            if (parameter.code == code) {
                int response_body_length = parameter.device_response.size();
                if (response_body_length > 1 && response_body_length <= MAX_RESPONSE_LEN - 1 - 2) {
                    int n = response_body_length - 1;
                    std::copy(parameter.device_response.begin() + 1, 
                            parameter.device_response.begin() + 1 + n, 
                            response_body);
                    std::cout << parameter.name << std::endl;
                } else {
                    std::cout << "Bad response body length" << std::endl;
                    return 0;
                }
                return response_body_length;
            }
        }

        std::cout << "Parameter not foud" << std::endl;
        return 0;
    }

    // Заполнение тела ответа на запрос текущих показаний
    uint16_t fill_response_body(uint8_t code, uint8_t array_code, uint8_t* response_body) {

        // Поиск по коду запроса
        for (const auto& data : datas) {
            if (data.code == code) {

                // Поиск по коду массива
                std::vector<DataItem> arrays = data.array;
                for (const auto& array: arrays) {
                    if (array.array_code == array_code) {
                        int response_body_length = array.device_response.size();
                        if (response_body_length > 1 && 
                            response_body_length <= MAX_RESPONSE_LEN - 1 - 2) {
                            int n = response_body_length - 1;
                            std::copy(array.device_response.begin() + 1, 
                            array.device_response.begin() + 1 + n, 
                            response_body);
                            std::cout << array.array_description << std::endl;
                        } else {
                            std::cout << "Bad response body length" << std::endl;
                            return 0;
                        }
                        return response_body_length;

                    }
                }
            }
        }

        std::cout << "Array of measurements not foud" << std::endl;
        return 0;
    }

    // Обработка запроса
    size_t process_request(uint8_t address, uint8_t* request_body, size_t body_length, uint8_t* response_body) {
        size_t response_length = 0;
        response_body[0] = address;

        switch (request_body[0]) {
            default: break;
           
            // Тестирование, открытие и закрытие канала связи
            case 0x00: case 0x01: case 0x02:
                response_body[1] = 0x00;
                response_length = 2;
                break;

            // Чтение параметров
            case 0x08:
                response_length = fill_response_body(request_body[1], &response_body[1]);
                break;
            
            // Чтение учтённой энергии и максимумов мощности
            case 0x05: case 0x15: case 0x17: case 0x18:
                response_length = fill_response_body(request_body[0], request_body[1], &response_body[1]);
                break;
        }

        return response_length;
    }
};

// Открытие сокета
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

        // Имитация задержек
        srand(time(0));
        if (enable_latency && rand() % 10 < 3) { // шанс ~30%
            usleep(1000); // 1мс
        }

        // Имитация потери пакетов
        if (enable_packet_loss && rand() % 10 < 2) { // шанс ~20%
            continue;
        }

        // Чтение запроса
        ssize_t request_length = read(newsockfd, request, sizeof(request));
        if (request_length < 0) {
            std::cerr << "Failed to read from socket.\n";
        } else if (request_length == 0) {
            std::cout << "Client disconnected.\n";
        }

#if 0
        // Имитация искажений запросов
        if (enable_distortion && rand() % 10 < 1) { // шанс ~10%
            request[rand() % request_length] ^= 0xFF;
        }
#endif

        std::cout << "Request: ";
        print_message(request, request_length);

        // Подготовка ответа
        size_t response_length;
        handler.handle(request, request_length, response, response_length);

        // Имитация искажений ответов
        if (enable_distortion && rand() % 10 < 1) { // шанс ~10%
            response[rand() % response_length] ^= 0xFF;
        }

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
    std::string settings_path;
    std::string data_path;
    std::string mode;
    int port = 8000;
    bool help = false;

    while ((opt = getopt(argc, argv, "s:d:m:p:h")) != -1)  
    {  
        switch (opt)  
        {  
            case 's':  
                settings_path = optarg;
                break;
            case 'd':
                data_path = optarg; 
            case 'm':  
                if (strchr(optarg, 'l')) enable_latency = true;
                if (strchr(optarg, 'p')) enable_packet_loss = true;
                if (strchr(optarg, 'i')) enable_distortion = true;
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
        std::cout << "Usage: ./mercury234 -s <path_to_settings_json> -d <path_to_data_json> -m <mode> [l][p][i] -p <tcp_port> [-h]" << std::endl;
        std::cout << "-s: Path to the settings JSON file" << std::endl;
        std::cout << "-d: Path to the data JSON file" << std::endl;
        std::cout << "-m: Mode (latency, packet loss, distortion)" << std::endl;
        std::cout << "-p: TCP port to open" << std::endl;
        std::cout << "-h: Display this help message" << std::endl;
        std::cout << std::endl;
    } else {
        std::cout << "-s: Path to the settings JSON file: " << settings_path << std::endl;
        std::cout << "-d: Path to the data JSON file: " << data_path << std::endl;
        std::cout << "Mode: " << enable_latency << enable_packet_loss << enable_distortion << std::endl;
        std::cout << "TCP Port: " << port << std::endl;
        std::cout << std::endl;

        // Загрузка json-файла с параметрами
        std::ifstream ifss(settings_path);
        if (!ifss.is_open()) {
            std::cerr << "Failed to open settings JSON file" << std::endl;
            return 1;
        }

        json s;
        try {
            ifss >> s;
        }
        catch (json::parse_error& e) {
            std::cerr << "Failed to parse the settings JSON file: " << e.what() << std::endl;
            return 1;
        }

        // Загрузка json-файла с текущими показаниями
        std::ifstream ifsd(data_path);
        if (!ifsd.is_open()) {
            std::cerr << "Failed to open data JSON file" << std::endl;
            return 1;
        }

        json d;
        try {
            ifsd >> d;
        }
        catch (json::parse_error& e) {
            std::cerr << "Failed to parse the JSON file: " << e.what() << std::endl;
            return 1;
        }

        // Заполнение массива параметров
        json parameters = s["parameters"];
        for (const auto& parameter : parameters) {

            // Запрос (код параметра)
            uint8_t code = hex_string_to_byte(parameter["code"].get<std::string>());

            // Наименование
            std::string name = parameter["name"];

            // Ответ
            std::string device_response_hex = parameter["device_response"];
            std::vector<uint8_t> device_response = hex_string_to_vector(device_response_hex);

            // Описание
            std::string device_response_description = parameter["device_response_description"];

            // Заполнение массива параметров
            params.push_back(Parameter(code, name, device_response, device_response_description));
        }

        // Заполнение массива показаний
        json data_arrays = d["data"];
        for (const auto& data_element : data_arrays) {

            // Код параметра (запрос)
            uint8_t code = hex_string_to_byte(data_element["code"].get<std::string>());
            
            std::vector<DataItem> arrs;
            for (const auto& array_element : data_element["array"]) {

                // Код массива (запрос)
                uint8_t array_code = hex_string_to_byte(array_element["array_code"].get<std::string>());

                // print_message(&array_code, 1);

                // Ответ
                std::string device_response_hex = array_element["device_response"];
                std::vector<uint8_t> device_response = hex_string_to_vector(device_response_hex);

                // Описание
                std::string array_description = array_element["array_description"];
                
                arrs.push_back(DataItem(array_code, device_response, array_description));
            }

            datas.push_back(Data(code, arrs));
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
