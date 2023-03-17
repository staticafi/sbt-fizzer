#define _CRT_SECURE_NO_WARNINGS 1
#include <utility/log.hpp>
#include <utility/timestamp.hpp>
#include <utility/assumptions.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <vector>
#include <iostream>
#include <sstream>
#include <ctime>
#include <thread>
#if COMPILER() == COMPILER_VC()
#   pragma warning(disable:4996) // warning C4996: 'localtime': This function or variable may be unsafe. Consider using localtime_s instead.
#endif


static logging_severity_level global_minimal_severity_level = LSL_DEBUG;


std::string const& logging_severity_level_name(logging_severity_level const level)
{
    static std::vector<std::string> level_names{ "debug", "info", "warning", "error", "testing" };
    ASSUMPTION(static_cast<unsigned int>(level) < level_names.size());
    return level_names.at(static_cast<unsigned int>(level));
}


logging_severity_level logging_get_minimal_severity_level()
{
    return global_minimal_severity_level;
}


void  logging_set_minimal_severity_level(logging_severity_level const level)
{
    ASSUMPTION(level >= logging_severity_level::LSL_DEBUG && level <= logging_severity_level::LSL_FATAL);
    global_minimal_severity_level = level;
}


html_file_logger& html_file_logger::instance()
{
    static html_file_logger  logger;
    return logger;
}


html_file_logger::html_file_logger()
    : m_log_file_ptr(nullptr)
    , m_mutex()
{}


html_file_logger::~html_file_logger()
{
    close();
}


bool  html_file_logger::open(std::string const& log_file_path_name)
{
    close();

    std::lock_guard<std::mutex> lock(m_mutex);

    std::string const file_name = [](std::string const& log_file_name) {
            std::filesystem::path  fpath = log_file_name;
            if (fpath.extension().string().empty())
                fpath.replace_extension(".html");
            return extend_file_path_name_by_timestamp(fpath.string(), "_LOG");
            }(log_file_path_name);

    m_log_file_ptr = std::make_unique<std::ofstream>(file_name, std::ios_base::app);
    if (m_log_file_ptr == nullptr)
        return false;
    if (!m_log_file_ptr->good())
    {
        close();
        return false;
    }
    *m_log_file_ptr
        <<  "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "    <meta charset=\"UTF-8\">\n"
            "    <title>LOG-FILE: " << file_name << "</title>\n"
            "    <style type=\"text/css\">\n"
            "        body\n"
            "        {\n"
            "            font-family:arial;\n"
            "            font-size:10px;\n"
            "        }\n"
            "        table,th,td\n"
            "        {\n"
            "            border:1px solid black;\n"
            "            border-collapse:collapse;\n"
            "        }\n"
//         "        th,td\n"
//         "        {\n"
//         "            padding:5px;\n"
//         "        }\n"
//         "        th\n"
//         "        {\n"
//         "            text-align:left;\n"
//         "        }\n"
            "   </style>\n"
            "</head>\n"
            "<body>\n"
//         "    <table style=\"width:300px\">\n"
            "    <table>\n"
            "    <tr>\n"
            "        <th>Time stamp</th>\n"
            "        <th>Thread ID</th>\n"
            "        <th>File</th>\n"
            "        <th>Line</th>\n"
            "        <th>Level</th>\n"
            "        <th>Message</th>\n"
            "    </tr>\n"
            ;
    return m_log_file_ptr->good();
}


void  html_file_logger::close()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_log_file_ptr != nullptr)
    {
        if (m_log_file_ptr->good())
            *m_log_file_ptr << "    </table>\n</body>\n</html>\n";
        m_log_file_ptr->close();
        m_log_file_ptr = nullptr;
    }
}


void  html_file_logger::append(logging_severity_level const level, std::string const& file, int const line, std::string const& message)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_log_file_ptr == nullptr)
        return;
    if (level < logging_get_minimal_severity_level())
        return;

    auto const  now = std::chrono::system_clock::now();
    auto const  time_t = std::chrono::system_clock::to_time_t(now);
    auto const  ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    *m_log_file_ptr
        << "    <tr>\n"
        << "        <td>" << std::put_time(std::localtime(&time_t), "%Y-%m-%d--%H:%M:%S.") << ms.count() << "</td>\n"
        << "        <td>" << std::this_thread::get_id() << "</td>\n"
        << "        <td>" << file << "</td>\n"
        << "        <td>" << line << "</td>\n"
        << "        <td>" << logging_severity_level_name(level) << "</td>\n"
        << "        <td>" << message << "</td>\n"
        << "    </tr>\n"
        ;

    m_log_file_ptr->flush();
}


screen_text_logger&  screen_text_logger::instance()
{
    static screen_text_logger  logger;
    return logger;
}


screen_text_logger::screen_text_logger()
    : m_text()
    , m_max_size(25000U)
{}


void  screen_text_logger::set_max_text_size(std::size_t const  max_size)
{
    m_max_size = max_size; append("");
};


void  screen_text_logger::append(std::string const&  text)
{
    m_text += text;
    if (m_text.size() > m_max_size)
        m_text.resize(m_max_size);
}


continuous_text_logger&  continuous_text_logger::instance()
{
    static continuous_text_logger  logger;
    return logger;
}


continuous_text_logger::continuous_text_logger()
    : m_lines()
    , m_max_line_size(250U)
    , m_max_num_line(100U)
{}


void  continuous_text_logger::append(std::string const&  text)
{
    m_lines.push_front(text);
    if (m_lines.front().size() > m_max_line_size)
        m_lines.front().resize(m_max_line_size);
    while (m_lines.size() > m_max_num_line)
        m_lines.pop_back();
}


std::string  continuous_text_logger::text() const
{
    std::stringstream  sstr;
    for (auto  rit = m_lines.rbegin(); rit != m_lines.rend(); ++rit)
        sstr << *rit << std::endl;
    return sstr.str();
}
