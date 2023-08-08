#ifndef CONNECTION_BENCHMARK_EXECUTOR_HPP_INCLUDED
#   define CONNECTION_BENCHMARK_EXECUTOR_HPP_INCLUDED

#   include <connection/client_executor.hpp>
#   include <connection/target_executor.hpp>
#   include <connection/server.hpp>
#   include <utility/basic_numeric_types.hpp>
#   include <memory>
#   include <string>


namespace connection {


struct  benchmark_executor
{
    virtual  ~benchmark_executor() {}
    virtual void  operator()() = 0;
    virtual void  on_io_config_changed() {}
};


struct  benchmark_executor_via_network : public benchmark_executor
{
    benchmark_executor_via_network(
            std::string const&  path_to_client,
            std::string const&  path_to_target,
            int const  port
            );
    ~benchmark_executor_via_network();
    void  operator()() override;

private:
    std::unique_ptr<server>  serv;    
    std::unique_ptr<client_executor>  executor;
};


struct  benchmark_executor_via_shared_memory : public benchmark_executor
{
    benchmark_executor_via_shared_memory(std::string const&  path_to_target);
    ~benchmark_executor_via_shared_memory();
    void  operator()() override;
    void  on_io_config_changed() override;

private:
    std::unique_ptr<target_executor>  executor;
};


}

#endif
