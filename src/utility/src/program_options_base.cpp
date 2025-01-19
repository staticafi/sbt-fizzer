#include <utility/program_options_base.hpp>
#include <utility/msgstream.hpp>
#include <utility/log.hpp>
#include <utility/assumptions.hpp>
#include <boost/algorithm/string.hpp>
#include <unordered_set>


static std::vector<std::string> const  empty_vector;
static std::string const  empty_string;
static std::string const  zero_arity = "0";


bool  arity_leq(std::size_t const  arity, std::string const& arity_spec)
{
    if (arity_spec == "+")
        return arity <= 1UL;
    else if (arity_spec == "*")
        return true;
    else
        return arity <= (std::size_t)std::stoi(arity_spec);
}

bool  is_arity_valid(std::size_t const  arity, std::string const& arity_spec)
{
    if (arity_spec == "+")
        return arity >= 1UL;
    else if (arity_spec == "*")
        return true;
    else
        return arity == (std::size_t)std::stoi(arity_spec);
}


program_options_base::program_options_base(int argc, char* argv[])
    : m_values()
    , m_descriptions()
    , m_arities()
    , m_positional()
    , m_arguments()
    , m_parsed(false)
{
    for (int i = 0; i < argc; ++i)
    {
        m_arguments.push_back(argv[i]);
        boost::algorithm::trim(m_arguments.back());
    }
}


std::size_t  program_options_base::size() const
{
    return m_values.size();
}


std::size_t  program_options_base::num_arguments() const
{
    return m_arguments.size();
}


bool  program_options_base::has(std::string const& key) const
{
    const_cast<program_options_base*>(this)->parse();
    return m_values.count(key) != 0UL;
}


std::vector<std::string> const&  program_options_base::values(std::string const& key) const
{
    const_cast<program_options_base*>(this)->parse();
    auto const  it = m_values.find(key);
    return it != m_values.end() ? it->second : empty_vector;
}


std::string const&  program_options_base::value(std::string const& key) const
{
    std::vector<std::string> const& v = values(key);
    return v.empty() ? empty_string : v.front();
}


int  program_options_base::value_as_int(std::string const& key) const
{
    return std::stoi(value(key));
}


float  program_options_base::value_as_float(std::string const& key) const
{
    return std::stof(value(key));
}


std::string const&  program_options_base::description(std::string const& key) const
{
    auto const  it = m_descriptions.find(key);
    return it != m_descriptions.end() ? it->second : empty_string;
}


std::string const& program_options_base::arity(std::string const& key) const
{
    auto const  it = m_arities.find(key);
    return it != m_arities.end() ? it->second : zero_arity;
}


void  program_options_base::set_value(std::string const& key)
{
    ASSUMPTION(m_descriptions.count(key) != 0UL);
    m_values[key] = {};
}


void  program_options_base::add_value(std::string const& key, std::string const& value)
{
    ASSUMPTION(m_descriptions.count(key) != 0UL);
    m_values[key].push_back(value);
    ASSUMPTION(arity_leq(m_values.at(key).size(), arity(key)));
}


void  program_options_base::add_positional_option(std::string const& key, std::string const& description)
{
    add_option(key, description, "1");
    m_positional.push_back(key);
}


void  program_options_base::add_option(std::string const& key, std::string const& description, std::string const& arity)
{
    ASSUMPTION(!key.empty() && m_descriptions.count(key) == 0UL && !description.empty() && !arity.empty());
    m_descriptions[key] = description;
    m_arities[key] = arity;
}


std::ostream& program_options_base::operator<<(std::ostream& ostr) const
{
    ostr << "Positional options:\n";
    for (std::size_t i = 0U; i != m_positional.size(); ++i)
        ostr << "  " << m_positional.at(i) << "  " << arity(m_positional.at(i)) << "  " << description(m_positional.at(i)) << "\n";
    ostr << "Options:\n";
    std::unordered_set  positionals(m_positional.begin(), m_positional.end());
    for (auto const&  key_desc : m_descriptions)
        if (positionals.count(key_desc.first) == 0UL)
            ostr << "  " << key_desc.first << "  " << arity(key_desc.first) << "  " << key_desc.second << "\n";
    return ostr;
}


void  program_options_base::parse()
{
    if (m_parsed)
        return;
    m_parsed = true;

    bool  failed = false;
    bool  visited_non_positional = false;
    std::string  processed_key;
    std::size_t  processed_i;
    for (std::size_t  i = 1U; i < m_arguments.size(); ++i)
    {
        std::string const&  arg = m_arguments.at(i);
        if (boost::starts_with(arg, "--"))
        {
            visited_non_positional = true;
            if (!processed_key.empty() && !is_arity_valid(values(processed_key).size(), arity(processed_key)))
            {
                LOG(LSL_ERROR, "In argument " << i << ", --" << processed_key << ": wrong number of values. "
                               "Expected " << arity(processed_key) << ", but passed " << values(processed_key).size());
                failed = true;
            }
            processed_key = arg.substr(2);
            processed_i = i;
            if (m_descriptions.count(processed_key) == 0UL)
            {
                LOG(LSL_ERROR, "In positional argument " << i << ": the option '--" << processed_key << "' is unknown.");
                failed = true;
                break;
            }
            else
                set_value(processed_key);
        }
        else if (!processed_key.empty())
            add_value(processed_key, arg);
        else if (!visited_non_positional)
        {
            if (i >= m_positional.size())
            {
                if (i == m_positional.size())
                    LOG(LSL_ERROR, "In positional argument " << i << ": too many positional arguments");
                failed = true;
                continue;
            }
            if (!values(m_positional.at(i)).empty() || !is_arity_valid(1, arity(m_positional.at(i))))
            {
                LOG(LSL_ERROR, "In positional argument " << i << ": wrong number of values. "
                    "Expected 1, but has " << values(m_positional.at(i)).size());
                failed = true;
            }
            add_value(m_positional.at(i), arg);
        }
        else
        {
            LOG(LSL_ERROR, "In argument " << i << ": positional argument after non-positional.");
            failed = true;
        }
    }
    if (!processed_key.empty() && !is_arity_valid(values(processed_key).size(), arity(processed_key)))
    {
        LOG(LSL_ERROR, "In argument " << processed_i << ", --" << processed_key << ": wrong number of values. "
            "Expected " << arity(processed_key) << ", but passed " << values(processed_key).size());
        failed = true;
    }

    if (failed)
        throw std::runtime_error("Processing program options has failed. See the log file for more details.");
}


program_options_default::program_options_default(int argc, char* argv[])
    : program_options_base(argc, argv)
{
    add_option("help", "Produces this help message.", "0");
    add_option("version", "Prints the version string.", "0");
}
