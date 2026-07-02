if(NOT DEFINED CHECKMODULE_EXECUTABLE)
  message(FATAL_ERROR "CHECKMODULE_EXECUTABLE is not set")
endif()
if(NOT DEFINED SEMODULE_PACKAGE_EXECUTABLE)
  message(FATAL_ERROR "SEMODULE_PACKAGE_EXECUTABLE is not set")
endif()
if(NOT DEFINED FRDP_SELINUX_POLICY)
  message(FATAL_ERROR "FRDP_SELINUX_POLICY is not set")
endif()
if(NOT DEFINED FRDP_SELINUX_FILE_CONTEXTS)
  message(FATAL_ERROR "FRDP_SELINUX_FILE_CONTEXTS is not set")
endif()
if(NOT DEFINED FRDP_SELINUX_WORK_DIR)
  message(FATAL_ERROR "FRDP_SELINUX_WORK_DIR is not set")
endif()

file(REMOVE_RECURSE "${FRDP_SELINUX_WORK_DIR}")
file(MAKE_DIRECTORY "${FRDP_SELINUX_WORK_DIR}")

set(module_file "${FRDP_SELINUX_WORK_DIR}/frdpd.mod")
set(package_file "${FRDP_SELINUX_WORK_DIR}/frdpd.pp")

execute_process(
  COMMAND "${CHECKMODULE_EXECUTABLE}" -M -m -o "${module_file}" "${FRDP_SELINUX_POLICY}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "SELinux policy compile failed: ${stderr}\n${stdout}")
endif()

execute_process(
  COMMAND "${SEMODULE_PACKAGE_EXECUTABLE}" -o "${package_file}" -m "${module_file}" -f "${FRDP_SELINUX_FILE_CONTEXTS}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "SELinux policy package failed: ${stderr}\n${stdout}")
endif()
