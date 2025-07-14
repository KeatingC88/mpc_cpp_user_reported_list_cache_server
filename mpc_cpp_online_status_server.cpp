#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>

#include "crow_all.h"
#include <tacopie/tacopie>

#include "jwt-cpp/jwt.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <vector>
#include <stdexcept>
#include <iostream>

#include <cpp_redis/cpp_redis>

void loadEnvFile(const std::string& path = ".env") {
    std::ifstream file(path);

    if (!file.is_open()) {
        std::cerr << "Could not open .env file\n";
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream lineStream(line);
        std::string key, value;

        if (std::getline(lineStream, key, '=') &&
            std::getline(lineStream, value)) {
            //setenv(key.c_str(), value.c_str(), 1);  Linux/MacOS
            _putenv_s(key.c_str(), value.c_str());
        }
    }
}

crow::SimpleApp app;
cpp_redis::client client;

std::vector<unsigned char> base64_decode(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.data(), input.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> output(input.length());
    int len = BIO_read(bio, output.data(), static_cast<int>(input.length()));
    output.resize(len > 0 ? len : 0);

    BIO_free_all(bio);
    return output;
}

std::vector<unsigned char> sha256(const std::string& input) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash.data());
    return hash;
}

std::string aes256_decrypt(const std::string& base64_ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {
    if (key.size() != 32 || iv.size() != 16) {
        throw std::runtime_error("Key must be 32 bytes and IV must be 16 bytes");
    }

    std::vector<unsigned char> ciphertext = base64_decode(base64_ciphertext);
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create context");

    int len = 0, plaintext_len = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()))
        throw std::runtime_error("DecryptInit failed");

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
        throw std::runtime_error("DecryptUpdate failed");

    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
        throw std::runtime_error("DecryptFinal failed");

    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.end());
}

int main() 
{
    loadEnvFile();

    const char* HOST_IP_ADDRESS = std::getenv("HOST_IP_ADDRESS");
    const char* HOST_PORT_ADDRESS = std::getenv("HOST_PORT_ADDRESS");

    client.connect("127.0.0.1", 20346, [](const std::string& host, std::size_t port, cpp_redis::client::connect_state status) {
        if (status == cpp_redis::client::connect_state::dropped) {
            std::cerr << "Client disconnected from " << host << ":" << port << std::endl;
        }
    });

    CROW_ROUTE(app, "/set").methods(crow::HTTPMethod::Post)([](const crow::request& req) {

        const char* key_env = std::getenv("ENCRYPTION_KEY");
        const char* iv_env = std::getenv("ENCRYPTION_IV");

        if (!key_env || !iv_env) {
            return crow::response(500, "Missing ENCRYPTION_KEY or ENCRYPTION_IV");
        }

        std::string key_str = key_env;
        std::string iv_str = iv_env;

        if (iv_str.size() != 16) {
            return crow::response(500, "ENCRYPTION_IV must be exactly 16 characters long");
        }

        std::vector<unsigned char> key = sha256(key_str);
        std::vector<unsigned char> iv(iv_str.begin(), iv_str.end());

        auto body = crow::json::load(req.body);

        if (!body) return crow::response(400, "Invalid JSON");

        if (!body.has("user_id") || !body.has("status")) {
            return crow::response(400, "Missing required fields");
        }

        std::string enc_user = body["user_id"].s();
        std::string enc_status = body["status"].s();

        try {
            std::string decrypted_user = aes256_decrypt(enc_user, key, iv);
            std::string decrypted_status = aes256_decrypt(enc_status, key, iv);

            client.set(decrypted_user, decrypted_status);
            client.sync_commit();

            return crow::response(200, decrypted_user + ":" + decrypted_status);
        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] " << e.what() << std::endl;
            return crow::response(400, e.what());
        }
    });

    CROW_ROUTE(app, "/get").methods(crow::HTTPMethod::Post)([](const crow::request& req) {

        const char* key_env = std::getenv("ENCRYPTION_KEY");
        const char* iv_env = std::getenv("ENCRYPTION_IV");

        if (!key_env || !iv_env) {
            return crow::response(500, "Missing ENCRYPTION_KEY or ENCRYPTION_IV");
        }

        std::string key_str = key_env;
        std::string iv_str = iv_env;

        if (iv_str.size() != 16) {
            return crow::response(500, "ENCRYPTION_IV must be exactly 16 characters long");
        }

        std::vector<unsigned char> key = sha256(key_str);
        std::vector<unsigned char> iv(iv_str.begin(), iv_str.end());

        auto body = crow::json::load(req.body);

        if (!body) return crow::response(400, "Invalid JSON");

        if (!body.has("id")) {
            return crow::response(400, "Missing required fields");
        }

        std::string enc_user = body["id"].s();

        try {
            std::string decrypted_user_id = aes256_decrypt(enc_user, key, iv);

            auto get_reply_future = client.get(decrypted_user_id);
            client.sync_commit();

            cpp_redis::reply reply = get_reply_future.get();

            if (reply.is_null()) {
                return crow::response(404, "User ID not found");
            }

            return crow::response(200, reply.as_string());
        }
        catch (const std::exception& e) {
            std::cerr << "[ERROR] " << e.what() << std::endl;
            return crow::response(500, e.what());
        }

    });

    app.bindaddr(HOST_IP_ADDRESS).port(std::stoi(HOST_PORT_ADDRESS)).multithreaded().run();
}