set(THIS_TARGET_NAME benchmarks)

add_library(${THIS_TARGET_NAME}
    ./include/benchmarks/benchmarks.hpp
    ./src/benchmarks.cpp

    # actual benchmarks:

    ./src/c_string_count_chars.cpp
    ./src/c_string_parse_two_ints.cpp
    ./src/int16_equal.cpp
    ./src/int16_less.cpp
    ./src/nested_ifs.cpp

    ./src/float_if_x_eq_c.cpp

    ./src/int8_if_x_equal_c.cpp
    ./src/int8_if_x_equal_y_c.cpp
    ./src/int8_if_x_ge_c.cpp
    ./src/int8_if_x_lt_c.cpp
    ./src/int8_if_x_xor_a_eq_b.cpp
    ./src/int8_if_hash_x_y_z_eq_c.cpp

    ./src/int16_if_x_equal_c.cpp
    ./src/int16_if_x_equal_y_c.cpp
    ./src/int16_if_x_ge_c.cpp
    ./src/int16_if_x_lt_c.cpp
    ./src/int16_if_x_xor_a_eq_b.cpp
    ./src/int16_if_parabola.cpp

    ./src/uint16_if_parabola.cpp

    ./src/int32_if_x_equal_c.cpp
    ./src/int32_if_x_equal_y_c.cpp
    ./src/int32_if_x_ge_c.cpp
    ./src/int32_if_x_lt_c.cpp
    ./src/int32_if_x_xor_a_eq_b.cpp
    ./src/int32_if_parabola.cpp
    ./src/int32_logical_or_two_vars.cpp
    ./src/int32_ackermann.cpp

    ./src/uint32_if_parabola.cpp

    ./src/bool_flag_one_and_two.cpp
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib")
