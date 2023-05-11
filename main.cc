#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <zlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define BUFFER_SIZE 1024

using namespace std;

// 压缩函数，使用zlib库进行压缩
int compress_data(unsigned char* src_data, int src_len, unsigned char* dst_data, int dst_len) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        return ret;
    }
    strm.avail_in = src_len;
    strm.next_in = src_data;
    strm.avail_out = dst_len;
    strm.next_out = dst_data;
    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&strm);
        return ret == Z_OK ? Z_BUF_ERROR : ret;
    }
    int compressed_size = strm.total_out;
    deflateEnd(&strm);
    return compressed_size;
}

// RSA加密函数，使用OpenSSL库进行加密
int rsa_encrypt(unsigned char* src_data, int src_len, unsigned char* dst_data, RSA* rsa) {
    int encrypted_size = RSA_public_encrypt(src_len, src_data, dst_data, rsa, RSA_PKCS1_PADDING);
    if (encrypted_size == -1) {
        return -1;
    }
    return encrypted_size;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <server_ip> <server_port> <file_path>" << endl;
        exit(EXIT_FAILURE);
    }

    // 读取文件
    ifstream file(argv[3], ios::binary);
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    file.seekg(0, ios::end);
    int file_size = file.tellg();
    file.seekg(0, ios::beg);
    unsigned char* file_data = new unsigned char[file_size];
    file.read((char*)file_data, file_size);
    file.close();

    // 压缩文件
    int compressed_size = compressBound(file_size);
    unsigned char* compressed_data = new unsigned char[compressed_size];
    int ret = compress_data(file_data, file_size, compressed_data, compressed_size);
    if (ret != Z_OK) {
        cerr << "Failed to compress data." << endl;
        exit(EXIT_FAILURE);
    }

    // 初始化RSA密钥
    RSA* rsa = RSA_new();
    BIGNUM* bne = BN_new();
    if (BN_set_word(bne, RSA_F4) != 1 || RSA_generate_key_ex(rsa, 1024, bne, NULL) != 1) {
        cerr << "Failed to initialize RSA key." << endl;
        exit(EXIT_FAILURE);
    }
    BN_free(bne);

    // 加密压缩后的文件数据
    int encrypted_size = RSA_size(rsa);
    unsigned char* encrypted_data = new unsigned char[encrypted_size];
    ret = rsa_encrypt(compressed_data, compressed_size, encrypted_data, rsa);
    if (ret == -1) {
        cerr << "Failed to encrypt data." << endl;
        exit(EXIT_FAILURE);
    }

    // 建立网络连接
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);
    server_addr.sin_port = htons(atoi(argv[2]));
    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // 发送文件数据
    int sent_size = 0;
    int remaining_size = encrypted_size;
    while (remaining_size > 0) {
        int send_size = send(sock_fd, encrypted_data + sent_size, remaining_size, 0);
        if (send_size == -1) {
            perror("send");
            close(sock_fd);
            exit(EXIT_FAILURE);
        }
        sent_size += send_size;
        remaining_size -= send_size;
    }

    // 关闭连接
    close(sock_fd);
    delete[] file_data;
    delete[] compressed_data;
    delete[] encrypted_data;
    RSA_free(rsa);

    return 0;
}