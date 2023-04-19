#include <iostream>
#include <kleeient/program_options.hpp>
#include <kleeient/program_info.hpp>
#include <connection/kleeient.hpp>

int main(int argc, char* argv[]) {
    {
        initialise_program_options(argc,argv);
        if (get_program_options()->helpMode()) {
            std::cout << get_program_options();
        } else if (get_program_options()->versionMode()) {
            std::cout << get_program_version() << "\n";
        } else {
            boost::asio::io_context io_context;
            connection::kleeient kleeient = connection::kleeient::prepare_instance(io_context, get_program_options()->value("path"));
            kleeient.run(
                get_program_options()->value("address"),
                get_program_options()->value("port"));
            io_context.run();
        }
    }
    return 0;
}