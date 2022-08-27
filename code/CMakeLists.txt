# Here follow all libraries
include_directories(
    "${PROJECT_SOURCE_DIR}/code/utility/include"
    "${PROJECT_SOURCE_DIR}/code/instrumentation/include"
    "${PROJECT_SOURCE_DIR}/code/iomodels/include"
    "${PROJECT_SOURCE_DIR}/code/connection/include"
    "${PROJECT_SOURCE_DIR}/code/benchmarks/include"
    "${PROJECT_SOURCE_DIR}/code/client/include"
    "${PROJECT_SOURCE_DIR}/code/fuzzing/include"
    "${PROJECT_SOURCE_DIR}/code/fuzzhamm/include"
    )
message("Including the following libraries to the build:")
add_subdirectory(./utility)
    message("  utility")
add_subdirectory(./pass)
    message("  pass")
add_subdirectory(./instrumentation)
    message("  instrumentation")
add_subdirectory(./iomodels)
    message("  iomodels")
add_subdirectory(./connection)
    message("  connection")
add_subdirectory(./benchmarks)
    message("  benchmarks")
add_subdirectory(./client)
    message("  client")
add_subdirectory(./fuzzing)
    message("  fuzzing")
add_subdirectory(./fuzzhamm)
    message("  fuzzhamm")

# Here follow tools, if they should be included.
if(NOT DEFINED FIZZ_BUILD_ALSO_TOOLS)
    set(FIZZ_BUILD_ALSO_TOOLS "Yes" CACHE STRING "Build also tools? (Yes/No)" FORCE)
endif()
message("Build also tools: " ${FIZZ_BUILD_ALSO_TOOLS})
string( TOLOWER "${FIZZ_BUILD_ALSO_TOOLS}" FIZZ_TEMPORARY_VARIBLE)
if(FIZZ_TEMPORARY_VARIBLE STREQUAL "yes")
    include_directories("${PROJECT_SOURCE_DIR}/code/tools")
    add_subdirectory(./tools)
endif()
