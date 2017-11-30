find_package(Git)

if(GIT_FOUND)
  execute_process(
       COMMAND ${GIT_EXECUTABLE} describe --tags --dirty
       OUTPUT_VARIABLE GIT_VERSION_STRING_FULL
       RESULT_VARIABLE GIT_DESCRIBE_RESULT
       OUTPUT_STRIP_TRAILING_WHITESPACE
  )
else()
  set(GIT_DESCRIBE_RESULT -1)
endif()

# CMAKE_SOURCE_DIR is valid even before project() is called.
if(NOT GIT_DESCRIBE_RESULT EQUAL 0)
  file(READ ${CMAKE_SOURCE_DIR}/VERSION GIT_VERSION_STRING_FULL)
endif()

# Find major, minor, patch
string(REGEX REPLACE "^v|-.*$" "" GIT_VERSION_STRING "${GIT_VERSION_STRING_FULL}")
