#include "crow_all.h"
#include <cpp_redis/cpp_redis>
#include <tacopie/tacopie>
#include <string>


cpp_redis::client client;

int main() 
{
    client.connect("127.0.0.1", 20346, [](const std::string& host, std::size_t port, cpp_redis::client::connect_state status) {
        if (status == cpp_redis::client::connect_state::dropped) {
            std::cerr << "Client disconnected from " << host << ":" << port << std::endl;
        }
    });

    crow::SimpleApp app;
    
    CROW_ROUTE(app, "/set/<uint>/<int>")([](unsigned int user_id, int online_status) {

        std::string user_id_string = std::to_string(user_id);
        std::string online_status_string = std::to_string(online_status);

        client.set(user_id_string, online_status_string);
        client.sync_commit();
        return crow::response(200, user_id_string + ":" + online_status_string);

    });


    CROW_ROUTE(app, "/get/<uint>")([](unsigned int user_id) {

        std::string user_id_string = std::to_string(user_id);

        auto get_reply_future = client.get(user_id_string);

        client.sync_commit();

        cpp_redis::reply reply = get_reply_future.get();

        return crow::response(200, reply.as_string());

    });


    app.bindaddr("127.0.0.1").port(3003).multithreaded().run();
}