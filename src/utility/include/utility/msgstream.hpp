#ifndef UTILITY_MSGSTREAM_HPP_INCLUDED
#   define UTILITY_MSGSTREAM_HPP_INCLUDED

#   include <string>
#   include <sstream>


struct  msgstream
{
    struct end {};
    template<typename T>
    msgstream&  operator<<(T const& value) { m_stream << value; return *this; }
    std::string  get() const { return m_stream.str(); }
    operator std::string() const { return get(); }
    std::string  operator<<(end const&) const { return get(); }
    std::string  operator<<(end (*)()) const { return get(); }
private:
    std::ostringstream  m_stream;
};

inline constexpr msgstream::end  endmsg() noexcept { return {}; }


#endif
