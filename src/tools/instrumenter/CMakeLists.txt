set(THIS_TARGET_NAME instrumenter)

add_executable(${THIS_TARGET_NAME}
    program_info.hpp
    program_info.cpp

    program_options.hpp
    program_options.cpp

    main.cpp
    run.cpp

    llvm_instrumenter.hpp
    llvm_instrumenter.cpp
    )

# This if-else statement is here to allow using LLVM
# installed using Ubuntu's package manager. Sadly,
# Linux user prefer this over intallation of LLVM
# to VCPKG. (The similar issue is related to 'boost')
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
else()
    include_directories(${LLVM_INCLUDE_DIRS})
    # link_directories(${LLVM_LIBRARY_DIRS})
    # add_definitions(${LLVM_DEFINITIONS})
endif()


target_link_libraries(${THIS_TARGET_NAME}
    utility
    ${LLVM_LIST_OF_LIBRARIES_TO_LINK_WITH}
    )

set_target_properties(${THIS_TARGET_NAME} PROPERTIES
    DEBUG_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Debug"
    RELEASE_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_Release"
    RELWITHDEBINFO_OUTPUT_NAME "${THIS_TARGET_NAME}_${CMAKE_SYSTEM_NAME}_RelWithDebInfo"
    )

install(TARGETS ${THIS_TARGET_NAME} DESTINATION "tools")
install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Release/" OPTIONAL DESTINATION "tools" FILES_MATCHING PATTERN "*.dll")
install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/RelWithDebInfo/" OPTIONAL DESTINATION "tools" FILES_MATCHING PATTERN "*.dll")
install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/Debug/" OPTIONAL DESTINATION "tools" FILES_MATCHING PATTERN "*.dll")
