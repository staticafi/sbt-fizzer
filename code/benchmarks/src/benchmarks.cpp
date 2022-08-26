#include <benchmarks/benchmarks.hpp>

#define REGISTER_BENCHMARK(NAMESPACE)                                   \
    namespace NAMESPACE { DRIVER_(); }                                  \
    volatile bool __registrator_ ## NAMESPACE = []() -> bool {          \
        const_cast<benchmarks_map&>(get_benchmarks_map())               \
            .insert({ #NAMESPACE, NAMESPACE::DRIVER_NAME_ });           \
        return true;                                                    \
        }()

namespace benchmarks {


benchmarks_map const&  get_benchmarks_map()
{
    static benchmarks_map bm;
    return bm;
}

REGISTER_BENCHMARK(c_string_count_chars);
REGISTER_BENCHMARK(c_string_parse_two_ints);
REGISTER_BENCHMARK(int16_equal);
REGISTER_BENCHMARK(int16_less);
REGISTER_BENCHMARK(nested_ifs);

REGISTER_BENCHMARK(float_if_x_eq_c);

REGISTER_BENCHMARK(int8_if_x_equal_c);
REGISTER_BENCHMARK(int8_if_x_equal_y_c);
REGISTER_BENCHMARK(int8_if_x_ge_c);
REGISTER_BENCHMARK(int8_if_x_lt_c);
REGISTER_BENCHMARK(int8_if_x_xor_a_eq_b);
REGISTER_BENCHMARK(int8_if_hash_x_y_z_eq_c);

REGISTER_BENCHMARK(int16_if_x_equal_c);
REGISTER_BENCHMARK(int16_if_x_equal_y_c);
REGISTER_BENCHMARK(int16_if_x_ge_c);
REGISTER_BENCHMARK(int16_if_x_lt_c);
REGISTER_BENCHMARK(int16_if_x_xor_a_eq_b);
REGISTER_BENCHMARK(int16_if_parabola);

REGISTER_BENCHMARK(uint16_if_parabola);

REGISTER_BENCHMARK(int32_if_x_equal_c);
REGISTER_BENCHMARK(int32_if_x_equal_y_c);
REGISTER_BENCHMARK(int32_if_x_ge_c);
REGISTER_BENCHMARK(int32_if_x_lt_c);
REGISTER_BENCHMARK(int32_if_x_xor_a_eq_b);
REGISTER_BENCHMARK(int32_if_parabola);
REGISTER_BENCHMARK(int32_logical_or_two_vars);
REGISTER_BENCHMARK(int32_ackermann);

REGISTER_BENCHMARK(uint32_if_parabola);

REGISTER_BENCHMARK(bool_flag_one_and_two);


}
