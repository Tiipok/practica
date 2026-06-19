#include "app/cli_parser.h"
#include "app/experiment_runner.h"
#include <iostream>

int main(int argc, char* argv[]) {
    std::cout << "=== ZIP Bruteforce Research Tool ===\n"
              << "=== Apple Silicon M4 Performance Analysis ===\n"
              << std::endl;

    auto config_opt = app::CliParser::parse(argc, argv);
    if (!config_opt) {
        return 1;
    }

    app::ExperimentRunner runner(*config_opt);
    runner.run_all();

    return 0;
}
