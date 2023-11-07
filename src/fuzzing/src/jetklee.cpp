#include <fuzzing/jetklee.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/process.hpp>
#include <boost/process/child.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/filesystem.hpp>
#include <boost/dll.hpp>
#include <thread>
#include <iostream>
#include <fstream>
#include <exception>

namespace fuzzing {

jetklee::jetklee()
{
}

jetklee::jetklee(const std::string& program_path)
{
    auto installation_dir = boost::dll::program_location().parent_path();
    auto jetklee_executable_path = installation_dir/"JetKlee/build/bin/klee";
    auto jetklee_libs_path = installation_dir/"JetKlee/build/runtime/lib";
    auto traces = std::string("traces");
    auto models = std::string("models");

    auto output_dir = installation_dir/"klee-output/";
    auto traces_path = output_dir/traces;
    auto models_path = output_dir/models;

    if (boost::filesystem::exists(output_dir))
        boost::filesystem::remove_all(output_dir);
    boost::filesystem::create_directory(output_dir);

    if (mkfifo(traces_path.c_str(), S_IRUSR | S_IWUSR) == -1) {
        throw std::runtime_error("Could not create traces pipe");
    }
    if (mkfifo(models_path.c_str(), S_IRUSR | S_IWUSR) == -1) {
        throw std::runtime_error("Could not create models pipe");
    }

    auto env = boost::this_process::environment();
    env["KLEE_RUNTIME_LIBRARY_PATH"] = jetklee_libs_path.string();

    this->jetklee_thread = std::thread([&]() {
        running = true;
        auto process = boost::process::child(
            jetklee_executable_path,
            env,
            boost::process::args({
                "--output-dir", output_dir.string(),
                "--use-interactive-search",
                "--interactive-search-file", traces_path.string(),
                "--write-ktests=false",
                "--dump-states-on-halt=false",
                "--write-json",
                "--json-path", models, // relative to `output_dir`
                program_path,
            }));
        process.wait();
        running = false;
        if (process.exit_code() != 0)
        {
            std::cerr << "JetKlee exited with non-zero code" << std::endl;
        }
    });
    this->models = std::move(std::ifstream(models_path));
    this->traces = std::move(std::ofstream(traces_path));
}

bool jetklee::is_running()
{
    return running;
}


void jetklee::join()
{
    models.close();
    traces.close();
    jetklee_thread.join();
}

bool jetklee::get_model(const std::vector<bool> trace, std::vector<uint8_t>& model)
{
    try
    {
        std::cout << "Received following trace:" << std::endl;
        for (bool dir : trace)
        {
            std::cout << dir;
            traces << (dir ? "1" : "0");
        }
        traces << std::endl << std::flush;

        std::cout << std::endl;

        std::cout << "jetklee responded with following JSON:" << std::endl;
        std::string json_string;
        std::getline(models, json_string);
        std::cout << json_string << std::endl;

        auto json_stream = std::stringstream(json_string);
        boost::property_tree::ptree json;
        boost::property_tree::json_parser::read_json(json_stream, json);
        bool feasible = json.get<bool>("feasible");
        if (!feasible)
            return false;

        if (feasible)
        {
            BOOST_FOREACH(const boost::property_tree::ptree::value_type &v,
                        json.get_child("input_tc").get_child("bytes"))
            {
                model.push_back(v.second.get_value<uint8_t>());
            }
        }
        return true;
    }
    catch (...)
    {
        return false;
    }
}

}
