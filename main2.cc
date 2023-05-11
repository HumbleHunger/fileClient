// 发送数据
bool sendData(int sockfd, const std::vector<unsigned char>& data) {
int len = data.size();
if (send(sockfd, &len, sizeof(len), 0) != sizeof(len)) {
std::cerr << "Failed to send data size" << std::endl;
return false;
}
if (send(sockfd, data.data(), data.size(), 0) != len) {
    std::cerr << "Failed to send data" << std::endl;
    return false;
}

return true;
}

// 接收数据
bool recvData(int sockfd, std::vector<unsigned char>& data) {
int len;
if (recv(sockfd, &len, sizeof(len), MSG_WAITALL) != sizeof(len)) {
std::cerr << "Failed to receive data size" << std::endl;
return false;
}

data.resize(len);
if (recv(sockfd, data.data(), len, MSG_WAITALL) != len) {
    std::cerr << "Failed to receive data" << std::endl;
    return false;
}

return true;

}

int main(int argc, char* argv[]) {
if (argc != 4) {
std::cerr << "Usage: " << argv[0] << " [IP address] [port number] [file name]" << std::endl;
return 1;
}

const char* ip = argv[1];
int port = std::stoi(argv[2]);
const char* fileName = argv[3];

// 压缩文件
std::string compressedFileName = std::string(fileName) + ".gz";
if (!compressFile(fileName, compressedFileName)) {
    return 1;
}

// 加密文件
std::string publicKeyFile = "public_key.pem";
std::vector<unsigned char> fileData;
std::ifstream compressedFile(compressedFileName, std::ios::binary);
if (!compressedFile) {
    std::cerr << "Failed to open file: " << compressedFileName << std::endl;
    return 1;
}

fileData.assign((std::istreambuf_iterator<char>(compressedFile)), std::istreambuf_iterator<char>());
std::vector<unsigned char> encryptedData;
if (!encryptData(publicKeyFile, fileData, encryptedData)) {
    return 1;
}

// 连接服务器
int sockfd = socket(AF_INET, SOCK_STREAM, 0);

const char* ip = argv[1];
int port = std::stoi(argv[2]);
const char* fileName = argv[3];

// 压缩文件
std::string compressedFileName = std::string(fileName) + ".gz";
if (!compressFile(fileName, compressedFileName)) {
    return 1;
}

// 加密文件
std::string publicKeyFile = "public_key.pem";
std::vector<unsigned char> fileData;
std::ifstream compressedFile(compressedFileName, std::ios::binary);
if (!compressedFile) {
    std::cerr << "Failed to open file: " << compressedFileName << std::endl;
    return 1;
}

fileData.assign((std::istreambuf_iterator<char>(compressedFile)), std::istreambuf_iterator<char>());
std::vector<unsigned char> encryptedData;
if (!encryptData(publicKeyFile, fileData, encryptedData)) {
    return 1;
}

// 连接服务器
int sockfd = socket(AF_INET, SOCK_STREAM, 0);
请继续



if (sockfd < 0) {
std::cerr << "Failed to create socket" << std::endl;
return 1;
}

struct sockaddr_in serverAddr;
memset(&serverAddr, 0, sizeof(serverAddr));
serverAddr.sin_family = AF_INET;
serverAddr.sin_addr.s_addr = inet_addr(ip);
serverAddr.sin_port = htons(port);

if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
std::cerr << "Failed to connect to server" << std::endl;
close(sockfd);
return 1;
}

// 发送加密数据
if (send(sockfd, encryptedData.data(), encryptedData.size(), 0) != (int)encryptedData.size()) {
std::cerr << "Failed to send encrypted data" << std::endl;
close(sockfd);
return 1;
}

// 接收响应
char buffer[BUFFER_SIZE];
int recvLen = recv(sockfd, buffer, BUFFER_SIZE, 0);
if (recvLen < 0) {
std::cerr << "Failed to receive response" << std::endl;
close(sockfd);
return 1;
}

// 解密响应
std::vector<unsigned char> decryptedData;
if (!decryptData(privateKeyFile, std::vector<unsigned char>(buffer, buffer + recvLen), decryptedData)) {
close(sockfd);
return 1;
}

// 判断响应是否成功
if (decryptedData.empty() || decryptedData[0] != 0) {
std::cerr << "Failed to process file: " << fileName << std::endl;
close(sockfd);
return 1;
}

std::cout << "File " << fileName << " has been successfully processed" << std::endl;

// 关闭socket
close(sockfd);
return 0;
}