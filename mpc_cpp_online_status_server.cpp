#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>

#include "crow_all.h"
#include <tacopie/tacopie>

#include "jwt-cpp/jwt.h"
#include <json.hpp>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <vector>
#include <stdexcept>
#include <iostream>

#include <cpp_redis/cpp_redis>

crow::SimpleApp app;
cpp_redis::client client;

std::vector<unsigned char> global_key;
std::vector<unsigned char> global_iv;

void Load_Env_File(const std::string& path = ".env") {
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
            _putenv_s(key.c_str(), value.c_str());
        }
    }
}

std::vector<unsigned char> Base64_Decoder(const std::string& input) {
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

std::vector<unsigned char> SHA256(const std::string& input) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash.data());
    return hash;
}

std::string AES256_Decryptor(const std::string& base64_ciphertext) {
    if (global_key.size() != 32 || global_iv.size() != 16) {
        throw std::runtime_error("Key must be 32 bytes and IV must be 16 bytes");
    }

    std::vector<unsigned char> ciphertext = Base64_Decoder(base64_ciphertext);
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create context");

    int len = 0, plaintext_len = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, global_key.data(), global_iv.data()))
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

int Authenticate_JWT_Claims(const std::string& JWT) {
    try {
        const char* JWT_ISSUER_KEY = std::getenv("JWT_ISSUER_KEY");
        const char* JWT_CLIENT_KEY = std::getenv("JWT_CLIENT_KEY");
        auto decoded = jwt::decode(JWT);
        auto payload_json = nlohmann::json::parse(decoded.get_payload());

        for (auto it = payload_json.begin(); it != payload_json.end(); ++it) {
            if (it.value().is_string()) {
                if (it.key() == "aud" && AES256_Decryptor(it.value()) != JWT_CLIENT_KEY) {
                    return 0;
                }
                else if (it.key() == "iss" && AES256_Decryptor(it.value()) != JWT_ISSUER_KEY) {
                    return 0;
                }
            }
            else if (std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) >= it.value()) {
                return 0;
            }
        }
        return 1;
    }
    catch (const std::exception& e) {
        return 0;
    }
}

int main()
{
    Load_Env_File();
    const char* HOST_IP_ADDRESS = std::getenv("HOST_IP_ADDRESS");
    const char* HOST_PORT_ADDRESS = std::getenv("HOST_PORT_ADDRESS");
    const char* REDIS_HOST_ADDRESS = std::getenv("REDIS_HOST_ADDRESS");
    const char* REDIS_PORT_ADDRESS = std::getenv("REDIS_PORT_ADDRESS");

    const char* key_env = std::getenv("ENCRYPTION_KEY");
    const char* iv_env = std::getenv("ENCRYPTION_IV");

    if (!key_env || !iv_env || std::strlen(key_env) != 32 || std::strlen(iv_env) != 16) {
        std::cerr << "Invalid key or IV in environment variables." << std::endl;
        return 1;
    }

    global_key = SHA256(key_env);
    global_iv = std::vector<unsigned char>(iv_env, iv_env + 16);

    client.connect(REDIS_HOST_ADDRESS, std::stoi(REDIS_PORT_ADDRESS), [](const std::string& host, std::size_t port, cpp_redis::client::connect_state status) {
        if (status == cpp_redis::client::connect_state::dropped) {
            std::cerr << "Client disconnected from " << host << ":" << port << std::endl;
        }
    });

    CROW_ROUTE(app, "/set").methods(crow::HTTPMethod::Post)([](const crow::request& req) {
        auto body = crow::json::load(req.body);

        if (!body || !body.has("id") || !body.has("online_status") || !body.has("token")) {
            return crow::response(400, "Missing Information");
        }

        std::string encrypted_user_id = body["id"].s();
        std::string encrypted_user_status = body["online_status"].s();
        std::string JWT = body["token"].s();

        if (!Authenticate_JWT_Claims(JWT)) {
            return crow::response(400, "Missing Information");
        }

        try {
            std::string decrypted_user = AES256_Decryptor(encrypted_user_id);
            std::string decrypted_status = AES256_Decryptor(encrypted_user_status);

            client.set(decrypted_user, decrypted_status);
            client.sync_commit();

            return crow::response(200, decrypted_user + ":" + decrypted_status);

        } catch (const std::exception& e) {
            return crow::response(400, e.what());
        }
    });

    CROW_ROUTE(app, "/get").methods(crow::HTTPMethod::Post)([](const crow::request& req) {
        auto body = crow::json::load(req.body);

        if (!body || !body.has("id") || !body.has("token")) {
            return crow::response(400, "Missing Information");
        }

        std::string encrypted_user_id = body["id"].s();
        std::string JWT = body["token"].s();

        if (!Authenticate_JWT_Claims(JWT)) {
            return crow::response(400, "Missing Information");
        }

        try {
            std::string decrypted_user_id = AES256_Decryptor(encrypted_user_id);

            auto get_reply_future = client.get(decrypted_user_id);
            client.commit();

            cpp_redis::reply reply = get_reply_future.get();

            if (reply.is_null()) {
                return crow::response(404, "User ID not found");
            }

            return crow::response(200, reply.as_string());
        } catch (const std::exception& e) {
            return crow::response(500, e.what());
        }
    });

    app.bindaddr(HOST_IP_ADDRESS).port(std::stoi(HOST_PORT_ADDRESS)).multithreaded().run();
}