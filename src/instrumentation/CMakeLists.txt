set(THIS_TARGET_NAME instrumentation)

add_library(${THIS_TARGET_NAME}
    ./include/instrumentation/instrumentation_types.hpp
    ./src/instrumentation_types.cpp

    ./include/instrumentation/data_record_id.hpp

    ./include/instrumentation/target_termination.hpp

    ./include/instrumentation/fuzz_target.hpp
    ./src/fuzz_target.cpp

    ./src/instrumentation.cpp

    ./src/verifier_functions.cpp

    ./src/main.cpp
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
