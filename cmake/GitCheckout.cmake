
function(try_checkout)
	message(STATUS "${ARGV0} doesn't exist. Try to checkout ...")
	find_package(Git REQUIRED)
	execute_process(
		COMMAND ${GIT_EXECUTABLE} submodule update --init -- ${ARGV1}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		RESULT_VARIABLE EXITCODE)
	if(NOT "${EXITCODE}" STREQUAL "0")
	  message(FATAL_ERROR "Checkout ${ARGV0} FAILED!")
	endif()
endfunction()
