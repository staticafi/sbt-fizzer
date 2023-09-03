#include <utility/timestamp.hpp>
#include <utility/config.hpp>
#include <chrono>
#include <filesystem>
#include <ctime>
#include <iomanip>
#include <sstream>


static std::string const  program_start_timestamp = compute_timestamp();


std::string const& get_program_start_timestamp()
{
    return program_start_timestamp;
}


std::string  compute_timestamp()
{
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
#   if COMPILER() == COMPILER_VC()
    struct tm timeinfo;
    localtime_s(&timeinfo, &t);
    std::tm* const ptm = &timeinfo;
#else
    std::tm* const ptm = std::localtime(&t);
#endif
    std::stringstream sstr;
    sstr << "--"
         << ptm->tm_year + 1900 << "-"
         << std::setfill('0') << std::setw(2)
         << ptm->tm_mon + 1 << "-"
         << std::setfill('0') << std::setw(2)
         << ptm->tm_mday << "--"
         << std::setfill('0') << std::setw(2)
         << ptm->tm_hour << "-"
         << std::setfill('0') << std::setw(2)
         << ptm->tm_min << "-"
         << std::setfill('0') << std::setw(2)
         << ptm->tm_sec
         ;
    return sstr.str();
}

std::string  extend_file_path_name_by_timestamp(
        std::string const& file_path_name,
        std::string const& suffix,
        bool const use_start_timestamp
        )
{
    std::filesystem::path const file(file_path_name);
    std::filesystem::path path = file.parent_path();
    std::filesystem::path name = file.filename().replace_extension("");
    std::filesystem::path ext = file.extension();
    return (path / (name.string() +
                   (use_start_timestamp ? get_program_start_timestamp() : compute_timestamp()) +
                   suffix +
                   ext.string())
           ).string();
}
