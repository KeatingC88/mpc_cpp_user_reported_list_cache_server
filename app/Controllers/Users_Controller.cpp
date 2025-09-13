
#include "Users_Controller.h"
#include "../Services/ENV/ENV.h"
#include "../Services/AES/AES.h"
#include "../Services/JWT/JWT.h"
#include "../Services/CORS/CORS.h" 

#include <cpp_redis/cpp_redis>
cpp_redis::client client;

#include <json.hpp>
using json = nlohmann::json;

namespace App::Controllers {

    void Users_Controller::RegisterRoutes(crow::App<CORS>& app) {

        App::Services::AES::AES AES;
        App::Services::JWT::JWT JWT;
        App::Services::ENV::ENV ENV;

        std::string REDIS_HOST_ADDRESS = ENV.Read("DOCKER_INTERNAL_REDIS_HOST_ADDRESS");
        std::string REDIS_PORT_ADDRESS = ENV.Read("DOCKER_INTERNAL_REDIS_PORT_ADDRESS");

        client.connect(REDIS_HOST_ADDRESS, std::stoi(REDIS_PORT_ADDRESS), [](const std::string& host, std::size_t port, cpp_redis::client::connect_state status) {
            if (status == cpp_redis::client::connect_state::dropped) {
                std::cerr << "Client disconnected from " << host << ":" << port << std::endl;
            }
            });

        CROW_ROUTE(app, "/set/user").methods(crow::HTTPMethod::Post)([JWT, AES](const crow::request& req) {
            auto body = crow::json::load(req.body);

            if (!body ||
                !body.has("id") ||
                !body.has("token") ||
                !body.has("online_status") ||
                !body.has("custom_lbl") ||
                !body.has("name") ||
                !body.has("created_on") ||
                !body.has("avatar_url_path") ||
                !body.has("avatar_title") ||
                !body.has("language_code") ||
                !body.has("region_code") ||
                !body.has("login_on") ||
                !body.has("logout_on") ||
                !body.has("login_type") ||
                !body.has("account_type") ||
                !body.has("email_address")
                ) {
                return crow::response(400, "Error: 1");//Something is missing from the condition.
            }

            std::string JWT_Client_Side_Token = body["token"].s();

            if (!JWT.Authenticate_Claims(JWT_Client_Side_Token)) {
                return crow::response(400, "Error: 2");//Something is incorrect in the JWToken.
            }

            try {

                std::string encrypted_user_id = body["id"].s();
                std::string decrypted_user_id = AES.Decrypt(encrypted_user_id);

                client.ltrim(decrypted_user_id, 1, 0);

                client.rpush(decrypted_user_id, {
                    encrypted_user_id,
                    body["online_status"].s(),
                    body["custom_lbl"].s(),
                    body["name"].s(),
                    body["created_on"].s(),
                    body["avatar_url_path"].s(),
                    body["avatar_title"].s(),
                    body["language_code"].s(),
                    body["region_code"].s(),
                    body["login_on"].s(),
                    body["logout_on"].s(),
                    body["login_type"].s(),
                    body["account_type"].s(),
                    body["email_address"].s()
                    });

                client.commit();

                return crow::response(200, decrypted_user_id);

            }
            catch (const std::exception& e) {

                return crow::response(400, "Error: 3");//Try catch failed.

            }
            });

        CROW_ROUTE(app, "/get/user").methods(crow::HTTPMethod::Post)([JWT, AES](const crow::request& req) {
            auto body = crow::json::load(req.body);

            if (!body ||
                !body.has("id") ||
                !body.has("token")
                ) {
                return crow::response(400, "Error 3");//Something is missing from the condition.
            }

            std::string JWT_Client_Side_Token = body["token"].s();
            if (!JWT.Authenticate_Claims(JWT_Client_Side_Token)) {
                return crow::response(400, "Error 4");//Something is incorrect in the JWToken.
            }

            try {

                std::string encrypted_user_id = body["id"].s();
                std::string decrypted_user_id = AES.Decrypt(encrypted_user_id);

                auto get_reply_future = client.lrange(decrypted_user_id, 0, -1);
                client.commit();

                cpp_redis::reply reply = get_reply_future.get();

                if (reply.is_null() || reply.is_array() == false) {
                    return crow::response(404, "Error 5");//Reply from the database is incorrect.
                }

                json j_object;

                size_t index = 0;

                for (const auto& element : reply.as_array()) {
                    std::string key;
                    switch (index) {
                    case 0: key = "id"; break;
                    case 1: key = "online_status"; break;
                    case 2: key = "custom_lbl"; break;
                    case 3: key = "name"; break;
                    case 4: key = "created_on"; break;
                    case 5: key = "avatar_url_path"; break;
                    case 6: key = "avatar_title"; break;
                    case 7: key = "language_code"; break;
                    case 8: key = "region_code"; break;
                    case 9: key = "login_on"; break;
                    case 10: key = "logout_on"; break;
                    case 11: key = "login_type"; break;
                    case 12: key = "account_type"; break;
                    case 13: key = "email_address"; break;
                    default: key = "unknown_" + std::to_string(index); break;
                    }

                    if (element.is_string()) {
                        j_object[key] = element.as_string();
                    }
                    else {
                        j_object[key] = nullptr;
                    }

                    ++index;
                }

                return crow::response(200, j_object.dump());

            }
            catch (const std::exception& e) {

                return crow::response(500, e.what());

            }
            });

        CROW_ROUTE(app, "/get/users").methods(crow::HTTPMethod::Post)([JWT](const crow::request& req) {
            auto body = crow::json::load(req.body);

            if (!body ||
                !body.has("token")
                ) {

                return crow::response(400, "Error 6");// missing conditions.

            }

            std::string JWT_Client_Side_Token = body["token"].s();

            if (!JWT.Authenticate_Claims(JWT_Client_Side_Token)) {
                return crow::response(400, "Error 7");//Something is incorrect in the JWToken.
            }

            try {

                std::vector<std::string> all_keys;
                std::size_t cursor = 0;
                std::size_t count = 100;
                json result_json;

                do {
                    auto future_reply = client.scan(cursor, count);
                    client.sync_commit();
                    cpp_redis::reply reply = future_reply.get();

                    if (!reply.is_array() || reply.as_array().size() != 2) {
                        std::cerr << "Error 8";//Scan Issue with future_reply.get()
                        break;
                    }

                    const auto& reply_arr = reply.as_array();
                    cursor = std::stoull(reply_arr[0].as_string());

                    const auto& keys_array = reply_arr[1].as_array();
                    for (const auto& k : keys_array) {
                        if (k.is_string()) {
                            all_keys.push_back(k.as_string());
                        }
                    }
                } while (cursor != 0);

                for (const auto& key : all_keys) {
                    auto lrange_future = client.lrange(key, 0, -1);
                    client.sync_commit();
                    cpp_redis::reply lrange_reply = lrange_future.get();

                    if (!lrange_reply.is_array()) continue;

                    json list_items = json::array();
                    for (const auto& item : lrange_reply.as_array()) {
                        if (item.is_string()) {
                            list_items.push_back(item.as_string());
                        }
                        else {
                            list_items.push_back(nullptr);
                        }
                    }

                    result_json[key] = list_items;
                }

                return crow::response(200, result_json.dump(2));

            }
            catch (const std::exception& e) {

                return crow::response(500, e.what());

            }
            });
    }

}