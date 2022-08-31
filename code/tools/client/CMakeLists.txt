set(THIS_TARGET_NAME client)

option(INSTRUMENTED_LLVM_FILE "Provide the path to the instrumented coded needed to compile the client")

if(INSTRUMENTED_LLVM_FILE)

    add_executable(${THIS_TARGET_NAME}
        ./client_options.hpp
        ./client_options.cpp

        ./run.cpp
        ./main.cpp
        )

    target_compile_options(${THIS_TARGET_NAME} PRIVATE -flto)
    target_link_options(${THIS_TARGET_NAME} PRIVATE -flto -fuse-ld=lld)

    target_link_libraries(${THIS_TARGET_NAME}
        instrumentation
        connection
        iomodels
        utility
        ${INSTRUMENTED_LLVM_FILE}
        ${BOOST_LIST_OF_LIBRARIES_TO_LINK_WITH}
        )


    set_target_properties(${THIS_TARGET_NAME} PROPERTIES
        DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
        RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
        RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
        )

    install(TARGETS ${THIS_TARGET_NAME} DESTINATION "tools")

endif()