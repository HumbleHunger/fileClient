#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

int main(int argc, char *argv[]) {
    // 传入的参数需包含要传输的文件路径以及服务器地址和端口号
    if (argc != 4) {
        cerr << "Usage: ./client [file_path] [server_address] [server_port]" << endl;
        exit(1);
    }

    // 获取传输文件信息
    string file_path = argv[1];
    ifstream infile(file_path, ios::binary);
    if (!infile) {
        cerr << "Failed to open file: " << file_path << endl;
        exit(1);
    }
    infile.seekg(0, infile.end);
    size_t file_size = infile.tellg();
    infile.seekg(0, infile.beg);
    cout << "File size: " << file_size << " bytes" << endl;

    // 与服务器建立连接
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        cerr << "Failed to create socket" << endl;
        exit(1);
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(argv[2]);
    server_addr.sin_port = htons(atoi(argv[3]));

    if (connect(client_fd, (sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        cerr << "Failed to connect to server" << endl;
        exit(1);
    }

    // 发送文件信息
    int64_t file_size_big_endian = htobe64(file_size);
    if (write(client_fd, &file_size_big_endian, sizeof(file_size_big_endian)) != sizeof(file_size_big_endian)) {
        cerr << "Failed to send file size" << endl;
        exit(1);
    }

    // 发送文件数据
    char buffer[4096];
    size_t total_bytes_sent = 0;
    while (!infile.eof()) {
        infile.read(buffer, sizeof(buffer));
        size_t bytes_sent = write(client_fd, buffer, infile.gcount());
        if (bytes_sent < 0) {
            cerr << "Failed to send file data" << endl;
            exit(1);
        }
        total_bytes_sent += bytes_sent;
    }

    cout << "File sent successfully, " << total_bytes_sent << " bytes sent" << endl;

    close(client_fd);
    return 0;
}