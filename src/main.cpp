#include "app/app.hpp"

#include <csignal>

int main(int argc, char** argv) {
    std::signal(SIGINT, ibmbrute_app::on_signal);
    std::signal(SIGTERM, ibmbrute_app::on_signal);
    return ibmbrute_app::run_cli(argc, argv);
}
