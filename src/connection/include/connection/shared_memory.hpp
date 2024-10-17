#ifndef CONNECTION_SHARED_MEMORY_HPP_INCLUDED
#   define CONNECTION_SHARED_MEMORY_HPP_INCLUDED

#   include <connection/medium.hpp>
#   include <boost/interprocess/shared_memory_object.hpp>
#   include <boost/interprocess/mapped_region.hpp>
#   include <utility/endian.hpp>
#   include <utility/assumptions.hpp>
#   include <instrumentation/target_termination.hpp>
#   include <connection/message.hpp>
#   include <optional>
#   include <stdexcept>

namespace  connection {


class shared_memory : public medium {
    inline static const char* segment_name = "SBT-Fizzer_Shared_Memory";

    boost::interprocess::shared_memory_object shm{};
    boost::interprocess::mapped_region region{};
    natural_32_bit cursor = 0;
    natural_8_bit* memory = nullptr;
    natural_32_bit* saved = nullptr;

public:

    shared_memory() : medium() {}

    natural_32_bit get_size() const;
    void set_size(natural_32_bit bytes);
    void clear() override;

    void open_or_create();
    void map_region();
    static void remove();

    bool can_accept_bytes(std::size_t n) const override;
    bool can_deliver_bytes(std::size_t n) const override;

    void accept_bytes(const void* src, std::size_t n) override;
    void deliver_bytes(void* dest, std::size_t n) override;

    void accept_bytes(message& src);
    void deliver_bytes(message& dest);

    bool exhausted() const;

    /*Interprets the first two bytes as termination type*/
    std::optional<instrumentation::target_termination> get_termination() const;
    /*Overwrites the first two bytes to set termination type*/
    void set_termination(instrumentation::target_termination termination) override;

    template<typename T, typename std::enable_if<std::is_trivially_copyable<T>::value, int>::type = 0>
    shared_memory& operator<<(const T& src)
    {
        accept_bytes(&src, sizeof(T));
        return *this;
    }

    shared_memory& operator<<(const std::string& src);

    template<typename T, typename std::enable_if<std::is_trivially_copyable<T>::value, int>::type = 0>
    shared_memory& operator>>(T& dest)
    {
        deliver_bytes(&dest, sizeof(T));
        return *this;
    }

    shared_memory& operator>>(std::string& dest);

};


}


#endif