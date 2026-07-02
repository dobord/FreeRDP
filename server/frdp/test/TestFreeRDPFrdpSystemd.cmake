if(NOT DEFINED SYSTEMD_ANALYZE_EXECUTABLE)
  message(FATAL_ERROR "SYSTEMD_ANALYZE_EXECUTABLE is not set")
endif()
if(NOT DEFINED FRDP_SYSTEMD_UNIT_DIR)
  message(FATAL_ERROR "FRDP_SYSTEMD_UNIT_DIR is not set")
endif()
if(NOT DEFINED FRDP_INSTALL_FULL_BINDIR)
  message(FATAL_ERROR "FRDP_INSTALL_FULL_BINDIR is not set")
endif()

set(test_root "${CMAKE_CURRENT_BINARY_DIR}/TestFreeRDPFrdpSystemd")
set(systemd_dir "${test_root}/etc/systemd/system")
set(install_bindir "${test_root}${FRDP_INSTALL_FULL_BINDIR}")

file(REMOVE_RECURSE "${test_root}")
file(MAKE_DIRECTORY "${systemd_dir}" "${install_bindir}")

foreach(unit frdpd.service frdp-authd.service frdp-sesmand.service)
  file(COPY "${FRDP_SYSTEMD_UNIT_DIR}/${unit}" DESTINATION "${systemd_dir}")
endforeach()

foreach(target sysinit.target basic.target network.target multi-user.target)
  file(WRITE "${systemd_dir}/${target}" "[Unit]\nDescription=${target}\n")
endforeach()

foreach(binary frdpd frdp-authd frdp-sesmand)
  file(WRITE "${install_bindir}/${binary}" "#!/bin/sh\nexit 0\n")
  file(CHMOD "${install_bindir}/${binary}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
       GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endforeach()

execute_process(
  COMMAND "${SYSTEMD_ANALYZE_EXECUTABLE}" verify "--root=${test_root}"
          frdpd.service frdp-authd.service frdp-sesmand.service
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "systemd-analyze verify failed with ${result}\nstdout:\n${stdout}\nstderr:\n${stderr}")
endif()
