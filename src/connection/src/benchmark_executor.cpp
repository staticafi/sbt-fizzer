#include <connection/benchmark_executor.hpp>
#include <iomodels/iomanager.hpp>

namespace connection {


benchmark_executor_via_network::benchmark_executor_via_network(
        std::string const&  path_to_client,
        std::string const&  path_to_target,
        int const  port
        )
    : benchmark_executor{}
    , serv{ nullptr }
    , executor{ nullptr }
{
    serv = std::make_unique<server>(port);
    serv->start();
    executor = std::make_unique<client_executor>(
        5,
        path_to_client + " --path_to_target " + path_to_target + " --port " + std::to_string(port),
        *serv
        );
    executor->start();
}


benchmark_executor_via_network::~benchmark_executor_via_network()
{
    if (executor != nullptr)
    {
        executor->stop();
        executor = nullptr;
    }
    if (serv != nullptr)
    {
        serv->stop();
        serv = nullptr;
    }
}


void benchmark_executor_via_network::operator()()
{
    serv->send_input_to_client_and_receive_result();
}


benchmark_executor_via_shared_memory::benchmark_executor_via_shared_memory(std::string const&  path_to_target)
    : benchmark_executor{}
    , executor{ nullptr }
{
    executor = std::make_unique<target_executor>(path_to_target);
    executor->set_timeout(iomodels::iomanager::instance().get_config().max_exec_milliseconds);
    executor->init_shared_memory(iomodels::iomanager::instance().get_config().required_shared_memory_size());
}


benchmark_executor_via_shared_memory::~benchmark_executor_via_shared_memory()
{
    executor = nullptr;
    shared_memory::remove();
}


void benchmark_executor_via_shared_memory::operator()()
{
    executor->get_shared_memory().clear();
    iomodels::iomanager::instance().get_config().save_target_config(executor->get_shared_memory());
    iomodels::iomanager::instance().get_stdin()->save(executor->get_shared_memory());
    iomodels::iomanager::instance().get_stdout()->save(executor->get_shared_memory());
    executor->execute_target();
    iomodels::iomanager::instance().clear_trace();
    iomodels::iomanager::instance().clear_br_instr_trace();
    iomodels::iomanager::instance().get_stdin()->clear();
    iomodels::iomanager::instance().get_stdout()->clear();
    iomodels::iomanager::instance().load_results(executor->get_shared_memory());
}


void benchmark_executor_via_shared_memory::on_io_config_changed()
{
    executor->init_shared_memory(iomodels::iomanager::instance().get_config().required_shared_memory_size());
}


}
