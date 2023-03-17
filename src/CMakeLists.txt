# Here follow all libraries
include_directories(
    "${PROJECT_SOURCE_DIR}/src/utility/include"
    "${PROJECT_SOURCE_DIR}/src/instrumentation/include"
    "${PROJECT_SOURCE_DIR}/src/iomodels/include"
    "${PROJECT_SOURCE_DIR}/src/connection/include"
    "${PROJECT_SOURCE_DIR}/src/benchmarks/include"
    "${PROJECT_SOURCE_DIR}/src/client/include"
    "${PROJECT_SOURCE_DIR}/src/fuzzing/include"
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
add_subdirectory(./fuzzing)
    message("  fuzzing")

# Here follow tools, if they should be included.
if(NOT DEFINED FIZZ_BUILD_ALSO_TOOLS)
    set(FIZZ_BUILD_ALSO_TOOLS "Yes" CACHE STRING "Build also tools? (Yes/No)" FORCE)
endif()
message("Build also tools: " ${FIZZ_BUILD_ALSO_TOOLS})
string( TOLOWER "${FIZZ_BUILD_ALSO_TOOLS}" FIZZ_TEMPORARY_VARIBLE)
if(FIZZ_TEMPORARY_VARIBLE STREQUAL "yes")
    include_directories("${PROJECT_SOURCE_DIR}/src/tools")
    add_subdirectory(./tools)
endif()
