set(THIS_TARGET_NAME utility)

add_library(${THIS_TARGET_NAME}
    ./include/utility/assumptions.hpp

    ./include/utility/basic_numeric_types.hpp

    ./src/bits_reference.cpp
    ./include/utility/bits_reference.hpp

    ./src/bit_count.cpp
    ./include/utility/bit_count.hpp

    ./include/utility/config.hpp

    ./include/utility/development.hpp

    ./include/utility/endian.hpp

    ./src/fail_message.cpp
    ./include/utility/fail_message.hpp

    ./include/utility/invariants.hpp

    ./src/log.cpp
    ./include/utility/log.hpp

    ./src/timestamp.cpp
    ./include/utility/timestamp.hpp

    ./src/timeprof.cpp
    ./include/utility/timeprof.hpp

    ./src/checked_number_operations.cpp
    ./include/utility/checked_number_operations.hpp

    ./src/random.cpp
    ./include/utility/random.hpp

    ./include/utility/typefn_if_then_else.hpp

    ./include/utility/msgstream.hpp

    ./include/utility/dynamic_linking.hpp
    
    ./include/utility/hash_combine.hpp     
    ./include/utility/std_pair_hash.hpp     

    ./include/utility/program_options_base.hpp
    ./src/program_options_base.cpp

    include/utility/math.hpp
    src/math.cpp
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

if(FIZZ_BUILD_LIBS_32_BIT STREQUAL "Yes")
    install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib32")
else()
    install(TARGETS ${THIS_TARGET_NAME} DESTINATION "lib")
endif()
