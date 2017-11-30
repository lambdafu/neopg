find_package(Git REQUIRED)
find_program(GEN_CHANGELOG github_changelog_generator)

if(NOT DEFINED ENV{v})
  MESSAGE(FATAL_ERROR "version not defined (use: make v=X.Y.Z)")
endif()

set(version "v$ENV{v}")
set(PROJECT_SOURCE_DIR "${s}")

MESSAGE("Version: ${version}")

file(WRITE ${PROJECT_SOURCE_DIR}/VERSION "${version}")

MESSAGE("Generating changelog...")
execute_process(
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND ${GEN_CHANGELOG} --header-label "\# Changelog" --future-release=${version}
)

execute_process(
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND sed -i -e "/This Change Log was automatically generated/d" ${PROJECT_SOURCE_DIR}/CHANGELOG.md
)

MESSAGE("Creating commit...")
execute_process(
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND ${GIT_EXECUTABLE} add VERSION CHANGELOG.md
)

execute_process(
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND ${GIT_EXECUTABLE} commit -m "Release ${version}."
)

execute_process(
  WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  COMMAND ${GIT_EXECUTABLE} tag "${version}"
)

MESSAGE("Now: git push; git push --tags")
