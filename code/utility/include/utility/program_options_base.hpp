#ifndef UTILITY_PROGRAM_OPTIONS_BASE_HPP_INCLUDED
#   define UTILITY_PROGRAM_OPTIONS_BASE_HPP_INCLUDED

#   include <unordered_map>
#   include <map>
#   include <vector>
#   include <string>
#   include <ostream>


class program_options_base
{
public:
    program_options_base(int argc, char* argv[]);

    std::size_t  size() const;
    std::size_t  num_arguments() const;

    bool  has(std::string const& key) const;
    std::vector<std::string> const& values(std::string const& key) const;
    std::string const&  value(std::string const& key) const;
    int  value_as_int(std::string const& key) const;
    float  value_as_float(std::string const& key) const;
    std::string const&  description(std::string const& key) const;
    std::string const&  arity(std::string const& key) const;

    void  set_value(std::string const& key);
    void  add_value(std::string const& key, std::string const& value);

    void  add_positional_option(std::string const&  key, std::string const&  description);
    void  add_option(std::string const&  key, std::string const&  description, std::string const&  arity);

    std::ostream& operator<<(std::ostream& ostr) const;

private:
    void  parse();

    std::unordered_map<std::string, std::vector<std::string> >  m_values;
    std::map<std::string, std::string>  m_descriptions;
    std::unordered_map<std::string, std::string>  m_arities;
    std::vector<std::string>  m_positional;
    std::vector<std::string>  m_arguments;
    bool  m_parsed;
};


class program_options_default : public program_options_base
{
public:
    program_options_default(int argc, char* argv[]);

    bool  helpMode() const { return has("help"); }
    bool  versionMode() const { return has("version"); }
    std::string const&  data_root() const { return value("data"); }
};


#endif
