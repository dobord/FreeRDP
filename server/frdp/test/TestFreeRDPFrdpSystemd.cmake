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

function(require_unit_line unit expected_line)
  file(READ "${FRDP_SYSTEMD_UNIT_DIR}/${unit}" unit_contents)
  string(FIND "${unit_contents}" "\n${expected_line}\n" line_index)
  if(line_index EQUAL -1)
    string(FIND "${unit_contents}" "${expected_line}\n" line_index)
  endif()
  if(line_index EQUAL -1)
    message(FATAL_ERROR "${unit} is missing required line: ${expected_line}")
  endif()
endfunction()

foreach(line
        "PrivateTmp=true"
        "PrivateDevices=true"
        "ProtectSystem=strict"
        "ProtectHome=true"
        "NoNewPrivileges=true"
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE"
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"
        "ProtectKernelTunables=true"
        "ProtectKernelModules=true"
        "ProtectKernelLogs=true"
        "ProtectClock=true"
        "ProtectHostname=true"
        "ProtectControlGroups=true"
        "RestrictRealtime=true"
        "RestrictSUIDSGID=true"
        "SystemCallArchitectures=native"
        "LockPersonality=true"
        "MemoryDenyWriteExecute=true"
        "UMask=0077"
        "LimitNOFILE=1024")
  require_unit_line(frdpd.service "${line}")
endforeach()

foreach(line
        "RuntimeDirectory=frdp-authd"
        "RuntimeDirectoryMode=0755"
        "PrivateTmp=true"
        "PrivateDevices=true"
        "ProtectSystem=strict"
        "ProtectHome=true"
        "ReadWritePaths=/run/frdp-authd /run/frdp-auth-token"
        "NoNewPrivileges=true"
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"
        "ProtectKernelTunables=true"
        "ProtectKernelModules=true"
        "ProtectKernelLogs=true"
        "ProtectClock=true"
        "ProtectHostname=true"
        "ProtectControlGroups=true"
        "RestrictRealtime=true"
        "RestrictSUIDSGID=true"
        "SystemCallArchitectures=native"
        "LockPersonality=true"
        "MemoryDenyWriteExecute=true"
        "UMask=0077"
        "LimitNOFILE=1024")
  require_unit_line(frdp-authd.service "${line}")
endforeach()

foreach(line
        "RuntimeDirectory=frdp-sesmand"
        "RuntimeDirectoryMode=0755"
        "PrivateTmp=true"
        "ProtectSystem=full"
        "ReadWritePaths=/run/frdp-sesmand /run/frdp-auth-token"
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"
        "ProtectKernelTunables=true"
        "ProtectKernelModules=true"
        "ProtectKernelLogs=true"
        "ProtectClock=true"
        "ProtectHostname=true"
        "RestrictRealtime=true"
        "SystemCallArchitectures=native"
        "LockPersonality=true"
        "UMask=0077"
        "LimitNOFILE=1024"
        "TasksMax=4096")
  require_unit_line(frdp-sesmand.service "${line}")
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
