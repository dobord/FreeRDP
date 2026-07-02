if(NOT DEFINED APPARMOR_PARSER_EXECUTABLE)
  message(FATAL_ERROR "APPARMOR_PARSER_EXECUTABLE is not set")
endif()
if(NOT DEFINED FRDP_APPARMOR_PROFILE)
  message(FATAL_ERROR "FRDP_APPARMOR_PROFILE is not set")
endif()

set(include_args)
if(EXISTS "/etc/apparmor.d")
  list(APPEND include_args -I /etc/apparmor.d)
endif()

execute_process(
  COMMAND "${APPARMOR_PARSER_EXECUTABLE}" -Q -K ${include_args} "${FRDP_APPARMOR_PROFILE}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "AppArmor profile validation failed: ${stderr}\n${stdout}")
endif()
