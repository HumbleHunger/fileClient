#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <algorithm>
#include <zlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int BUFFER_SIZE = 1029;

using namespace std;

bool AESencryptData(const std::vector<unsigned char> &key, const std::vector<unsigned char> &data, std::vector<unsigned char> &encryptedData)
{
    // 创建AES加密上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return false;
    }

    // 设置AES加密算法和密钥
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 分配足够的空间来保存加密后的数据
    encryptedData.resize(data.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

    // 执行AES加密
    int outLen;
    if (EVP_EncryptUpdate(ctx, encryptedData.data(), &outLen, data.data(), data.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 获取剩余的加密数据
    int finalLen;
    if (EVP_EncryptFinal_ex(ctx, encryptedData.data() + outLen, &finalLen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 更新加密后的数据长度
    encryptedData.resize(outLen + finalLen);

    // 释放AES加密上下文
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool AESdecryptData(const std::vector<unsigned char> &key, const std::vector<unsigned char> &data, std::vector<unsigned char> &decryptedData)
{
    // Set up the decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), NULL);

    // Allocate space for the output buffer
    decryptedData.resize(data.size());

    int outLen = 0;
    int totalLen = 0;
    int ret = 0;

    // Decrypt the data
    ret = EVP_DecryptUpdate(ctx, decryptedData.data(), &outLen, data.data(), data.size());
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    totalLen += outLen;

    ret = EVP_DecryptFinal_ex(ctx, decryptedData.data() + outLen, &outLen);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    totalLen += outLen;

    decryptedData.resize(totalLen);

    // Clean up and return
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool generateAESKey(const std::string& password, std::vector<unsigned char>& key) {
    const int keyLen = 16;
    const int saltLen = 16;
    const int iterationCount = 10000;

    key.resize(keyLen);

    unsigned char salt[saltLen];
    if (RAND_bytes(salt, saltLen) <= 0) {
        return false;
    }

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, saltLen, iterationCount,
                          EVP_sha256(), keyLen, key.data()) <= 0) {
        return false;
    }

    return true;
}

// 压缩文件
bool compressFile(const std::string &srcFile, const std::string &dstFile)
{
    //cout << dstFile << endl;
    gzFile out = gzopen(dstFile.c_str(), "wb");
    if (!out)
    {
        std::cerr << "Failed to open file: " << dstFile << std::endl;
        return false;
    }

    std::ifstream in(srcFile, std::ios::binary);
    if (!in)
    {
        std::cerr << "Failed to open file: " << srcFile << std::endl;
        return false;
    }

    char buf[1024];
    int len;
    while ((len = in.readsome(buf, sizeof(buf))) > 0)
    {
        if (gzwrite(out, buf, len) != len)
        {
            std::cerr << "Failed to compress file: " << srcFile << std::endl;
            return false;
        }
    }

    in.close();
    gzclose(out);
    return true;
}

// 解压缩文件
bool decompressFile(const std::string &srcFile, const std::string &dstFile)
{
    gzFile in = gzopen(srcFile.c_str(), "rb");
    if (!in)
    {
        std::cerr << "Failed to open file: " << srcFile << std::endl;
        return false;
    }

    std::ofstream out(dstFile, std::ios::binary);
    if (!out)
    {
        std::cerr << "Failed to open file: " << dstFile << std::endl;
        return false;
    }

    char buf[1024];
    int len;
    while ((len = gzread(in, buf, sizeof(buf))) > 0)
    {
        if (!out.write(buf, len))
        {
            std::cerr << "Failed to decompress file: " << srcFile << std::endl;
            return false;
        }
    }

    gzclose(in);
    out.close();
    return true;
}

bool encryptData(const std::string &publicKeyFile, const std::vector<unsigned char> &data, std::vector<unsigned char> &encryptedData)
{
    // 1. 从公钥文件加载RSA公钥
    FILE* publicKey = fopen(publicKeyFile.c_str(), "rb");
    if (!publicKey)
    {
        std::cerr << "Failed to open public key file." << std::endl;
        return false;
    }

    RSA* rsa = PEM_read_RSA_PUBKEY(publicKey, nullptr, nullptr, nullptr);
    if (!rsa)
    {
        std::cerr << "Failed to load RSA public key." << std::endl;
        return false;
    }

    // 2. 获取RSA密钥长度和块大小
    int keySize = RSA_size(rsa);
    int blockSize = keySize - 11; // 11是PKCS#1 v1.5填充的长度

    // 3. 对数据进行分段加密
    int dataSize = static_cast<int>(data.size());
    int numBlocks = (dataSize + blockSize - 1) / blockSize; // 计算块的数量

    std::vector<unsigned char> encryptedBuffer;
    encryptedBuffer.reserve(numBlocks * keySize); // 预先分配足够的空间

    for (int i = 0; i < numBlocks; ++i)
    {
        int offset = i * blockSize;
        int blockLength = std::min(blockSize, dataSize - offset);

        unsigned char* encryptedBlock = new unsigned char[keySize];
        int result = RSA_public_encrypt(blockLength, data.data() + offset, encryptedBlock, rsa, RSA_PKCS1_PADDING);
        if (result == -1)
        {
            std::cerr << "Failed to encrypt data block " << i << std::endl;
            RSA_free(rsa);
            delete[] encryptedBlock;
            return false;
        }

        encryptedBuffer.insert(encryptedBuffer.end(), encryptedBlock, encryptedBlock + result);
        delete[] encryptedBlock;
    }

    // 4. 将加密后的数据存储到向量中
    encryptedData = std::move(encryptedBuffer);

    // 5. 清理资源
    RSA_free(rsa);
    fclose(publicKey);

    return true;
}

bool decryptData(const std::string &privateKeyFile, const std::vector<unsigned char> &encryptedData, std::vector<unsigned char> &data)
{
    // 1. 从私钥文件加载RSA私钥
    FILE* privateKey = fopen(privateKeyFile.c_str(), "rb");
    if (!privateKey)
    {
        std::cerr << "Failed to open private key file." << std::endl;
        return false;
    }

    RSA* rsa = PEM_read_RSAPrivateKey(privateKey, nullptr, nullptr, nullptr);
    if (!rsa)
    {
        std::cerr << "Failed to load RSA private key." << std::endl;
        return false;
    }

    // 2. 获取RSA密钥长度和块大小
    int keySize = RSA_size(rsa);
    int blockSize = keySize;

    // 3. 对加密数据进行分段解密
    int encryptedSize = static_cast<int>(encryptedData.size());
    int numBlocks = encryptedSize / keySize; // 计算块的数量

    std::vector<unsigned char> decryptedBuffer;
    decryptedBuffer.reserve(numBlocks * blockSize); // 预先分配足够的空间

    for (int i = 0; i < numBlocks; ++i)
    {
        int offset = i * keySize;

        unsigned char* decryptedBlock = new unsigned char[blockSize];
        int result = RSA_private_decrypt(keySize, encryptedData.data() + offset, decryptedBlock, rsa, RSA_PKCS1_PADDING);
        if (result == -1)
        {
            std::cerr << "Failed to decrypt data block " << i << std::endl;
            RSA_free(rsa);
            delete[] decryptedBlock;
            return false;
        }

        decryptedBuffer.insert(decryptedBuffer.end(), decryptedBlock, decryptedBlock + result);
        delete[] decryptedBlock;
    }

    // 4. 将解密后的数据存储到向量中
    data = std::move(decryptedBuffer);

    // 5. 清理资源
    RSA_free(rsa);
    fclose(privateKey);

    return true;
}

/*
// 加密数据
bool encryptData(const std::string &publicKeyFile, const std::vector<unsigned char> &data, std::vector<unsigned char> &encryptedData)
{
    FILE *fp = fopen(publicKeyFile.c_str(), "rb");
    if (!fp)
    {
        std::cerr << "Failed to open file: " << publicKeyFile << std::endl;
        return false;
    }

    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if (!rsa)
    {
        std::cerr << "Failed to read public key: " << publicKeyFile << std::endl;
        fclose(fp);
        return false;
    }

    int rsaLen = RSA_size(rsa);
    encryptedData.resize(rsaLen);
    int ret = RSA_public_encrypt(data.size(), data.data(), encryptedData.data(), rsa, RSA_PKCS1_PADDING);
    if (ret != rsaLen)
    {
        std::cerr << "Failed to encrypt data" << std::endl;
        RSA_free(rsa);
        fclose(fp);
        return false;
    }

    RSA_free(rsa);
    fclose(fp);
    return true;
}

// 解密数据
bool decryptData(const std::string &privateKeyFile, const std::vector<unsigned char> &encryptedData, std::vector<unsigned char> &data)
{
    FILE *fp = fopen(privateKeyFile.c_str(), "rb");
    if (!fp)
    {
        std::cerr << "Failed to open file: " << privateKeyFile << std::endl;
        return false;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if (!rsa)
    {
        std::cerr << "Failed to read private key: " << privateKeyFile << std::endl;
        fclose(fp);
        return false;
    }

    int rsaLen = RSA_size(rsa);
    data.resize(rsaLen);
    int ret = RSA_private_decrypt(encryptedData.size(), encryptedData.data(), data.data(), rsa, RSA_PKCS1_PADDING);
    if (ret < 0)
    {
        std::cerr << "Failed to decrypt data" << std::endl;
        RSA_free(rsa);
        fclose(fp);
        return false;
    }

    data.resize(ret);
    RSA_free(rsa);
    fclose(fp);
    return true;
}
*/
// 发送数据
bool sendData(int sockfd, const std::vector<unsigned char> &data)
{
    int len = data.size();
    if (send(sockfd, &len, sizeof(len), MSG_WAITALL) != sizeof(len))
    {
        std::cerr << "Failed to send data size" << std::endl;
        return false;
    }
    if (send(sockfd, data.data(), data.size(), MSG_WAITALL) != len)
    {
        std::cerr << "Failed to send data" << std::endl;
        return false;
    }
    //cout << "sendData:: len: " << len  << " size " << sizeof(len) << endl;
    //cout << "sendData:: data: " << data.data()  << " size " << data.size() << endl;

    return true;
}

// 接收数据
bool recvData(int sockfd, std::vector<unsigned char> &data)
{
    int len;
    if (recv(sockfd, &len, sizeof(len), MSG_WAITALL) != sizeof(len))
    {
        std::cerr << "Failed to receive data size" << std::endl;
        return false;
    }

    data.resize(len);
    if (recv(sockfd, data.data(), len, MSG_WAITALL) != len)
    {
        std::cerr << "Failed to receive data" << std::endl;
        return false;
    }

    return true;
}

bool sendFile(int fd, string fileName, string password, string publicKeyFile)
{
    // 压缩文件
    std::string compressedFileName = std::string(fileName) + ".gz";
    //cout << compressedFileName << endl;
    if (!compressFile(fileName, compressedFileName))
    {
        cout << "Failed to compress file:" << fileName << endl;
        return false;
    }

    // 加密文件
    // 公钥文件
    std::vector<unsigned char> compressedFileData;
    std::ifstream compressedFile(compressedFileName, std::ios::binary);
    if (!compressedFile)
    {
        std::cerr << "Failed to open file: " << compressedFileName << std::endl;
        return false;
    }

    compressedFileData.assign((std::istreambuf_iterator<char>(compressedFile)), std::istreambuf_iterator<char>());
    std::vector<unsigned char> encryptedData;
    if (!encryptData(publicKeyFile, compressedFileData, encryptedData))
    {
        cout << "Failed to encrypt file:" << fileName << endl;
        return false;
    }

    // 打包数据
    vector<unsigned char> data;
    /*
        int len = 26 + encryptedData.size() + 1;

        unsigned char* clen = (unsigned char*)&len;
        for (int i = 0; i < 4; ++i) {
            data.push_back(clen[i]);
        }
    */
    string filedata = "UPLOAD";
    int len = fileName.size();
    char* lenp = (char*)&len;
    for (int i =0; i < 4; ++i) {
        filedata += lenp[i];
    }
    filedata += fileName;
    filedata += password;
    for (auto c : filedata)
    {
        data.push_back(c);
    }
    
    bool ret = sendData(fd, data);
    if (ret == false) {
        cout << "send file name failed" << endl;
        return ret;
    }

    data.resize(0);
    filedata = "FILE";

    for (int i =0; i < 4; ++i) {
        filedata += lenp[i];
    }
    filedata += fileName;

    for (auto c : filedata) {
        data.push_back(c);
    }

    for (auto c : encryptedData)
    {
        data.push_back(c);
    }

    ret = sendData(fd, data);

    char buffer[30];
    if (recv(fd, buffer, 20, MSG_WAITALL) != 20)
    {
        std::cerr << "Failed to receive data" << std::endl;
        ret = false;
    }    

    if (ret == false)
        cout << "Success send file" << fileName << endl;
    else
        cout << "Failed send file " << fileName << endl;

    return ret;
}

bool recvFile(int sockfd, string fileName, string password, string privateKeyFile)
{
    // 打包数据
    vector<unsigned char> data;

    string filedata = "DOWNLOAD";
    int len = fileName.size();
    char* lenp = (char*)&len;
    for (int i =0; i < 4; ++i) {
        filedata += lenp[i];
    }
    filedata += fileName;
    filedata += password;
    //filedata.resize(26);
    for (auto c : filedata)
    {
        data.push_back(c);
    }

    bool ret = sendData(sockfd, data);

    bool flag = false;
    vector<unsigned char> fileData;
    while (1)
    {
        // 接收响应
        char type[1];
        memset(type, 0, 1);
        int recvLen = recv(sockfd, type, 1, MSG_WAITALL);
        //cout << "recvfile:: type " << type[0] << endl;
        if (type[0] == '0') break;

        flag = true;
        char len[4];
        memset(len, 0, 4);
        recvLen = recv(sockfd, len, 4, MSG_WAITALL);
        //cout << "recvfile:: filedata len " << atoi(len) << endl;
        
        unsigned char buffer[atoi(len)];
        memset(buffer, 0, sizeof(buffer));
        recvLen = recv(sockfd, buffer, sizeof(buffer), MSG_WAITALL);
        //cout << "recvfile:: buffer recvLen is " << recvLen << endl;
        if (recvLen < 0)
        {
            std::cerr << "Failed to receive response" << std::endl;
            close(sockfd);
            return false;
        }
        
        for (auto c : buffer) {
            fileData.push_back(c);
        }
    }

    if (!flag) {
        cout << "file not exist or password error" << endl;
    }
/*
    cout << "file size is " << fileData.size() << endl;
    for (int i = 0; i < fileData.size(); ++i) {
        cout << fileData[i];
    }
    cout << endl;
*/
    // 解密响应
    // 私钥文件
    std::vector<unsigned char> decryptedData;
    if (!decryptData(privateKeyFile, fileData, decryptedData))
    {
        close(sockfd);
        return false;
    }

    // 判断响应是否成功
    //cout << "decrypted data size is" << decryptedData.size() << endl;
    //if (decryptedData.empty() || decryptedData[0] != 0)
    if (decryptedData.empty())
    {
        //std::cerr << "Failed to process file: " << fileName << std::endl;
        close(sockfd);
        return false;
    }

    string comFileName = fileName + ".gz";
    FILE *fp = fopen(comFileName.c_str(),"wb");
    if (fwrite(decryptedData.data(), sizeof(char), decryptedData.size(), fp) < decryptedData.size()) {
        printf("File:\t%s Write Failed\n", comFileName);
    }

    fclose(fp);

    if (!decompressFile(comFileName, fileName)) {
        cout << "Failed to decompress file " << fileName << endl;
        return false;
    }
    
    cout << "Success recv file " << fileName << endl;

    return true;
}

int main(int argc, char *argv[])
{
    if (argc != 6)
    {
        std::cerr << "Usage: " << argv[0] << " [IP address] [port number] [opeator] [file name] [password]" << std::endl;
        return 1;
    }

    const char *ip = argv[1];
    int port = std::stoi(argv[2]);
    const char *opeator = argv[3];
    const char *fileName = argv[4];
    const char *password = argv[5];
    const char *publicFile = "rsa_public_key.pem";
    const char *privateFile = "rsa_private_key.pem";
    // 连接服务器
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(ip);
    serverAddr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        std::cerr << "Failed to connect to server" << std::endl;
        close(sockfd);
        return 1;
    }

    bool ret = false;
    if (string(opeator) == "UPLOAD")
        ret = sendFile(sockfd, fileName, password, publicFile);
    else if (string(opeator) == "DOWNLOAD")
        ret = recvFile(sockfd, fileName, password, privateFile);
    else
    {
        cout << "opeator " << opeator << " is not support" << endl;
        return 1;
    }

    if (ret == false) {
        cout << opeator << " " << fileName  << " with " << password << " failed." << endl;
    }

    close(sockfd);
    return 0;
}