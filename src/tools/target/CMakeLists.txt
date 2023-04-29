set(THIS_TARGET_NAME sbt-fizzer_target)

set(FUZZ_TARGET_SOURCES 
    ./main.cpp
    )

set(FUZZ_TARGET_LIBS
    connection
    iomodels
    instrumentation
    iomodels
    utility
    )

add_library(fuzz_target_lib
    ${FUZZ_TARGET_SOURCES}
    )

target_link_libraries(fuzz_target_lib
    ${FUZZ_TARGET_LIBS}
    )

set_target_properties(fuzz_target_lib PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS fuzz_target_lib DESTINATION "lib")


option(INSTRUMENTED_LLVM_FILE "Provide the path to the instrumented coded needed to compile the client")

if(INSTRUMENTED_LLVM_FILE)

    add_executable(${THIS_TARGET_NAME}
        ${FUZZ_TARGET_SOURCES}
        )

    target_compile_options(${THIS_TARGET_NAME} PRIVATE -flto)
    target_link_options(${THIS_TARGET_NAME} PRIVATE -flto)

    target_link_libraries(${THIS_TARGET_NAME}
        ${INSTRUMENTED_LLVM_FILE}
        ${FUZZ_TARGET_LIBS}
        Threads::Threads
        )


    set_target_properties(${THIS_TARGET_NAME} PROPERTIES
        DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
        RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
        RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
        )

    install(TARGETS ${THIS_TARGET_NAME} DESTINATION "tools")

endif()