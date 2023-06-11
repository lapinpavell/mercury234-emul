#include <iostream>
#include <cstdint>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_CLIENTS 4
#define BUFFER_SIZE 1024
#define SOCKET_CREATION_FAILED -1
#define SOCKET_BINDING_FAILED -2
#define SOCKET_LISTEN_FAILED -3

struct client_data {
    int socket;
    //
};

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

// Тестирование канала связи
bool test_channel(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[4]  = {0x80, 0x00, 0x00, 0x00};  // запрос на тестирование канала связи
    uint8_t response[4] = {0x80, 0x00, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 2);
    uint8_t crc_high = crc >> 8;
    uint8_t crc_low = crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Test channel" << std::endl;

    // FIXME: почему-то перепутан порядок байт
    message[2] = crc_low;
    message[3] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 4);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }
    // read(sockfd, buffer, 4);

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
        send(sockfd, response, 4, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 4; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}

// Серийный номер и дата изготовления
bool get_sn_dof(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[5]  = {0x80, 0x08, 0x00, 0x00, 0x00};  // запрос на чтение серийного номера и даты изготовления
    uint8_t response[10] = {0x80, 0x29, 0x5A, 0x40, 0x43, 0x16, 0x06, 0x14, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 3);
    uint8_t crc_high = crc >> 8;
    uint8_t crc_low = crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Get serial number and date of manufacture" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[3] = crc_low;
    message[4] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 5);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }

    std::cout << "Message: ";
    for (int i = 0; i < 5; i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::endl;

    // Проверка соостветствия запроса
    if (memcmp(buffer, message, 5) == 0) {

        // Расчёт CRC ответа
        crc = crc16(response, 8);
        crc_high = crc >> 8;
        crc_low = crc & 0xFF;

        // FIXME: где-то перепутан порядок байт
        response[8] = crc_low;
        response[9] = crc_high;

        // Отправка ответа
        send(sockfd, response, 10, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 10; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}

// Открытие канала связи
bool open_channel(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[11]  = {0x80, 0x01, 0x01, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x00, 0x00 };  // запрос на открытие канала связи
    uint8_t response[4] = {0x80, 0x00, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 9);

    // FIXME: crc считается неправильно
    uint8_t crc_high = 0xA8; // crc >> 8;
    uint8_t crc_low = 0x48; // crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Open communication channel" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[9] = crc_low;
    message[10] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 11);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }

    std::cout << "Message: ";
    for (int i = 0; i < 11; i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::endl;

    // Проверка соостветствия запроса
    if (memcmp(buffer, message, 11) == 0) {

        // Расчёт CRC ответа
        crc = crc16(response, 2);
        crc_high = crc >> 8;
        crc_low = crc & 0xFF;

        // FIXME: почему-то перепутан порядок байт
        response[2] = crc_low;
        response[3] = crc_high;

        // Отправка ответа
        send(sockfd, response, 4, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 4; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}

// Версия ПО счётчика
bool get_firmware_version(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[5]  = {0x80, 0x08, 0x03, 0x00, 0x00}; // запрос на открытие канала связи
    uint8_t response[6] = {0x80, 0x09, 0x00, 0x00, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 3);

    uint8_t crc_high = crc >> 8;
    uint8_t crc_low  = crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Get firmware version" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[3] = crc_low;
    message[4] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 5);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }

    std::cout << "Message: ";
    for (int i = 0; i < 5; i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::endl;

    // Проверка соостветствия запроса
    if (memcmp(buffer, message, 5) == 0) {

        // Расчёт CRC ответа
        crc = crc16(response, 4);
        crc_high = crc >> 8;
        crc_low = crc & 0xFF;

        // FIXME: почему-то перепутан порядок байт
        response[4] = crc_low;
        response[5] = crc_high;

        // Отправка ответа
        send(sockfd, response, 6, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 6; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}

// Вариант исполнения
bool get_device_version(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[5]  = {0x80, 0x08, 0x12, 0x00, 0x00}; // запрос на открытие канала связи
    uint8_t response[9] = {0x80, 0xB4, 0xE3, 0xC2, 0x97, 0xDF, 0x58, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 3);

    uint8_t crc_high = crc >> 8;
    uint8_t crc_low  = crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Get device version" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[3] = crc_low;
    message[4] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 5);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }

    std::cout << "Message: ";
    for (int i = 0; i < 5; i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::endl;

    // Проверка соостветствия запроса
    if (memcmp(buffer, message, 5) == 0) {

        // Расчёт CRC ответа
        crc = crc16(response, 7);
        crc_high = crc >> 8;
        crc_low = crc & 0xFF;

        // FIXME: почему-то перепутан порядок байт
        response[7] = crc_low;
        response[8] = crc_high;

        // Отправка ответа
        send(sockfd, response, 9, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 9; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}

// Сетевой адрес
bool get_net_addr(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[5]  = {0x80, 0x08, 0x05, 0x00, 0x00}; // запрос на чтение сетевого адреса
    uint8_t response[5] = {0x80, 0x00, 0x80, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 3);

    uint8_t crc_high = crc >> 8;
    uint8_t crc_low  = crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Get network address" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[3] = crc_low;
    message[4] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 5);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }

    std::cout << "Message: ";
    for (int i = 0; i < 5; i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::endl;

    // Проверка соостветствия запроса
    if (memcmp(buffer, message, 5) == 0) {

        // Расчёт CRC ответа
        crc = crc16(response, 3);
        crc_high = crc >> 8;
        crc_low = crc & 0xFF;

        // FIXME: почему-то перепутан порядок байт
        response[3] = crc_low;
        response[4] = crc_high;

        // Отправка ответа
        send(sockfd, response, 5, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 5; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}

// Закрытие канала связи
bool close_channel(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[4]  = {0x80, 0x02, 0x00, 0x00}; // запрос на закрытие канала связи
    uint8_t response[4] = {0x80, 0x00, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 2);

    uint8_t crc_high = crc >> 8;
    uint8_t crc_low  = crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Close channel" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[2] = crc_low;
    message[3] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 4);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }

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
        send(sockfd, response, 4, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 4; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}

// Расширенный перечень параметров прибора
bool get_params_ext(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[6]  = {0x80, 0x08, 0x01, 0x00, 0x00, 0x00}; // запрос на расширенный перечень параметров
    uint8_t response[27] = {0x80, 0x20, 0x57, 0x2F, 0x42, 0x1A, 0x06, 0x12, 0x09, 0x00, 0x00, 0xB4, 0xE3, 0xC2, 0x97, 0xDF, 0x58, 0x7E, 0xF5, 0x32, 0x3A, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 4);

    uint8_t crc_high = crc >> 8;
    uint8_t crc_low  = crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Get extended list of parameters" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[4] = crc_low;
    message[5] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 6);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }

    std::cout << "Message: ";
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::endl;

    // Проверка соостветствия запроса
    if (memcmp(buffer, message, 6) == 0) {

        // Расчёт CRC ответа
        crc = crc16(response, 25);
        crc_high = crc >> 8;
        crc_low = crc & 0xFF;

        // FIXME: почему-то перепутан порядок байт
        response[25] = crc_low;
        response[26] = crc_high;

        // Отправка ответа
        send(sockfd, response, 27, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 27; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}

// CRC16 ПО счётчика
bool get_crc16(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[5]  = {0x80, 0x08, 0x26, 0x00, 0x00}; // запрос на чтение сетевого адреса
    uint8_t response[5] = {0x80, 0x7E, 0xF5, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 3);

    uint8_t crc_high = crc >> 8;
    uint8_t crc_low  = crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Get CRC16 of firmware version" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[3] = crc_low;
    message[4] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 5);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }

    std::cout << "Message: ";
    for (int i = 0; i < 5; i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::endl;

    // Проверка соостветствия запроса
    if (memcmp(buffer, message, 5) == 0) {

        // Расчёт CRC ответа
        crc = crc16(response, 3);
        crc_high = crc >> 8;
        crc_low = crc & 0xFF;

        // FIXME: почему-то перепутан порядок байт
        response[3] = crc_low;
        response[4] = crc_high;

        // Отправка ответа
        send(sockfd, response, 5, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 5; i++) {
            std::cout << std::hex << static_cast<int>(response[i]) << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "Received message does not match the specified byte sequence" << std::endl;
    }
}

// Коэффициент трансформации
bool get_trans_ratio(int sockfd) {
    uint8_t buffer[BUFFER_SIZE] = {0}; // буфер приёма
    uint8_t message[5]  = {0x80, 0x08, 0x02, 0x00, 0x00}; // запрос на чтение сетевого адреса
    uint8_t response[7] = {0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00}; // ответ на запрос

    // Расчёт CRC запроса
    uint16_t crc = crc16(message, 3);

    uint8_t crc_high = crc >> 8;
    uint8_t crc_low  = crc & 0xFF;

    // std::cout << "CRC16: " << std::hex << static_cast<int>(crc_high) << " " << static_cast<int>(crc_low) << std::endl;
    std::cout << "Get transformation ratio" << std::endl;

    // FIXME: где-то перепутан порядок байт
    message[3] = crc_low;
    message[4] = crc_high;

    // Чтение запроса
    ssize_t num_bytes = read(sockfd, buffer, 5);
    if (num_bytes < 0) {
        std::cerr << "Failed to read from socket.\n";
    } else if (num_bytes == 0) {
        std::cout << "Client disconnected.\n";
    } else {
        // buffer[num_bytes] = '\0';  // Null-terminate the string
        // std::cout << "Received message: " << buffer << '\n';
    }

    std::cout << "Message: ";
    for (int i = 0; i < 5; i++) {
        std::cout << std::hex << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::endl;

    // Проверка соостветствия запроса
    if (memcmp(buffer, message, 5) == 0) {

        // Расчёт CRC ответа
        crc = crc16(response, 5);
        crc_high = crc >> 8;
        crc_low = crc & 0xFF;

        // FIXME: почему-то перепутан порядок байт
        response[5] = crc_low;
        response[6] = crc_high;

        // Отправка ответа
        send(sockfd, response, 7, 0);
        std::cout << "Response sent: ";
        for (int i = 0; i < 7; i++) {
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

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Socket creation failed.\n";
        return SOCKET_CREATION_FAILED;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    // Forcefully attaching socket to the port
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Failed to bind socket to port " << port << ".\n";
        close(sockfd);
        return SOCKET_BINDING_FAILED;
    }
    
    if (listen(sockfd, MAX_CLIENTS) < 0) {
        std::cerr << "Failed to listen on socket.\n";
        close(sockfd);
        return SOCKET_LISTEN_FAILED;
    }

    std::cout << "Server listening on port " << port << ".\n";
    return sockfd;
}

// Обработка запросов
void* handle_client(void* arg) {
    client_data* data = static_cast<client_data*>(arg);
    int newsockfd = data->socket;

    test_channel(newsockfd); // Len=4
    get_sn_dof(newsockfd); // Len=5
    open_channel(newsockfd); // Len=11
    get_firmware_version(newsockfd); // Len=5?
    get_device_version(newsockfd);
    get_net_addr(newsockfd);
    open_channel(newsockfd);
    get_firmware_version(newsockfd);
    get_device_version(newsockfd);
    // close_channel(newsockfd);
    get_firmware_version(newsockfd);
    get_params_ext(newsockfd);
    get_device_version(newsockfd);
    get_params_ext(newsockfd);
    get_crc16(newsockfd);
    get_sn_dof(newsockfd);
    get_device_version(newsockfd);
    get_crc16(newsockfd);
    get_trans_ratio(newsockfd);

    close(newsockfd);
    delete data;
    return nullptr;
}

// Приём подключений
bool accept_connections(int sockfd) {
    struct sockaddr_in cli_addr; // адрес клиента
    socklen_t clilen = sizeof(cli_addr);
    
    while(true) {
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

        int sockfd = open_socket(port);

        if (!accept_connections(sockfd)) {
            std::cerr << "Failed to accept connections.\n";
            return 1;
        }
    }

    return 0;
}
