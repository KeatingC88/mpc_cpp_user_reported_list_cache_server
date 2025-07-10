#pragma warning(push)
#pragma warning(disable: 4267 4244 4305) // size_t → int usigned, etc.
#include "crow_all.h"
#pragma warning(pop)

int main() 
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([]() {
        return "Hello, World from C++ Web API!";
    });





    app.bindaddr("127.0.0.1").port(3003).multithreaded().run();
}