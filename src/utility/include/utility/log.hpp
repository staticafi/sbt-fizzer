#ifndef UTILITY_LOG_HPP_INCLUDED
#   define UTILITY_LOG_HPP_INCLUDED

#   include <utility/config.hpp>
#   include <utility/msgstream.hpp>
#   include <iosfwd>
#   include <memory>
#   include <string>
#   include <deque>
#   include <mutex>
#   if COMPILER() == COMPILER_VC()
#       pragma warning(disable : 26812) // do not say replace 'enum' by 'enum struct'.
#   endif

#   define LOG(LVL,MSG) \
        do {\
            if ((LVL) >= BUILD_RELEASE() * 2 && (LVL) >= logging_get_minimal_severity_level())\
            {\
                msgstream  mstr;\
                mstr << MSG;\
                html_file_logger::instance().append(LVL,__FILE__,__LINE__,mstr);\
            }\
        } while (false)
#   define LOG_INITIALISE(log_file_path_name,minimal_severity_level)\
        do {\
            logging_set_minimal_severity_level(minimal_severity_level);\
            html_file_logger::instance().open(log_file_path_name);\
        } while (false)
#   define SLOG(MSG) screen_text_logger::instance().append(msgstream() << MSG)
#   define CLOG(MSG) continuous_text_logger::instance().append(msgstream() << MSG)


enum logging_severity_level
{
    LSL_DEBUG = 0,
    LSL_INFO = 1,
    LSL_WARNING = 2,
    LSL_ERROR = 3,
    LSL_FATAL = 4,
};
std::string const&  logging_severity_level_name(logging_severity_level const level);
logging_severity_level  logging_get_minimal_severity_level();
void  logging_set_minimal_severity_level(logging_severity_level const level);


struct  html_file_logger
{
    static html_file_logger& instance();
    ~html_file_logger();

    bool  open(std::string const& log_file_path_name);
    void  append(logging_severity_level const level, std::string const& file, int const line, std::string const& message);
private:
    html_file_logger();
    void  close();
    std::unique_ptr<std::ofstream>  m_log_file_ptr;
    std::mutex  m_mutex;
};


struct  screen_text_logger
{
    static screen_text_logger&  instance();

    void  set_max_text_size(std::size_t const  max_size);

    void  clear() { m_text.clear(); }
    void  append(std::string const&  text);
    std::string const&  text() const { return m_text;}

private:
    screen_text_logger();

    std::string  m_text;
    std::size_t  m_max_size;
};


struct  continuous_text_logger
{
    static continuous_text_logger&  instance();

    void  set_line_max_size(std::size_t const  max_size) { m_max_line_size = max_size; }
    void  set_max_num_lines(std::size_t const  max_size) { m_max_num_line = max_size; }

    void  clear() { m_lines.clear(); }
    void  append(std::string const&  line);
    std::deque<std::string> const&  lines() const { return m_lines; }
    std::string  text() const;

private:
    continuous_text_logger();

    std::deque<std::string>  m_lines;
    std::size_t  m_max_line_size;
    std::size_t  m_max_num_line;
};


#endif
