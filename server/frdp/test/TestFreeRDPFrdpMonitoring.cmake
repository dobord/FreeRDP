if(NOT DEFINED BASH_EXECUTABLE)
  message(FATAL_ERROR "BASH_EXECUTABLE is not set")
endif()
if(NOT DEFINED FRDP_MONITORING_SCRIPT)
  message(FATAL_ERROR "FRDP_MONITORING_SCRIPT is not set")
endif()
if(NOT DEFINED FRDP_PROMETHEUS_ALERTS)
  message(FATAL_ERROR "FRDP_PROMETHEUS_ALERTS is not set")
endif()

set(test_root "${CMAKE_CURRENT_BINARY_DIR}/TestFreeRDPFrdpMonitoring")
set(fake_bin_dir "${test_root}/bin")
set(output_file "${test_root}/textfile/frdpd.prom")
set(fake_frdpctl "${fake_bin_dir}/frdpctl")

file(REMOVE_RECURSE "${test_root}")
file(MAKE_DIRECTORY "${fake_bin_dir}")

function(expect_contains haystack needle label)
  string(FIND "${haystack}" "${needle}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "${label} is missing '${needle}':\n${haystack}")
  endif()
endfunction()

file(WRITE "${fake_frdpctl}" [==[#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $# -ne 3 || $1 != status || $2 != --socket ]]; then
	echo "unexpected frdpctl invocation: $*" >&2
	exit 64
fi
case "${FRDP_FAKE_MODE:-ok}" in
	ok)
		printf 'Status: running\nActive sessions: 7\n'
		;;
	error)
		printf 'cannot reach socket %s\n' "$3" >&2
		exit 3
		;;
	*)
		echo "unknown fake mode" >&2
		exit 65
		;;
esac
]==])
file(CHMOD "${fake_frdpctl}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

set(success_socket "/tmp/frdp-\"quoted\"-socket")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=${fake_bin_dir}:$ENV{PATH}" FRDP_FAKE_MODE=ok
          "${BASH_EXECUTABLE}" "${FRDP_MONITORING_SCRIPT}" --socket "${success_socket}"
          --output "${output_file}" --max-connections 10
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "monitoring scrape success case failed: ${stderr}\n${stdout}")
endif()

file(READ "${output_file}" metrics)
foreach(expected
        "frdp_sesmand_reachable{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\"} 1"
        "frdp_exporter_scrape_success{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\"} 1"
        "frdp_sessions_active{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\"} 7"
        "frdp_sessions_max{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\"} 10")
  expect_contains("${metrics}" "${expected}" "successful scrape metrics")
endforeach()

set(error_socket "/tmp/frdp-error")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=${fake_bin_dir}:$ENV{PATH}" FRDP_FAKE_MODE=error
          "${BASH_EXECUTABLE}" "${FRDP_MONITORING_SCRIPT}" --socket "${error_socket}"
          --output "${output_file}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "monitoring scrape error case failed: ${stderr}\n${stdout}")
endif()

file(READ "${output_file}" metrics)
foreach(expected
        "frdp_sesmand_reachable{socket=\"/tmp/frdp-error\"} 0"
        "frdp_exporter_scrape_success{socket=\"/tmp/frdp-error\"} 0"
        "frdp_sessions_active{socket=\"/tmp/frdp-error\"} 0"
        "frdp_exporter_last_error{socket=\"/tmp/frdp-error\"} 1")
  expect_contains("${metrics}" "${expected}" "failed scrape metrics")
endforeach()
expect_contains("${metrics}" "# Last frdpctl scrape error: cannot reach socket /tmp/frdp-error"
                "failed scrape metrics")

execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=${fake_bin_dir}:$ENV{PATH}"
          "${BASH_EXECUTABLE}" "${FRDP_MONITORING_SCRIPT}" --socket "${success_socket}"
          --output "${output_file}" --max-connections 0
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 2)
  message(FATAL_ERROR "invalid max-connections returned ${result}, expected 2")
endif()
if(NOT stderr MATCHES "max connections must be a positive integer")
  message(FATAL_ERROR "invalid max-connections did not report the expected error: ${stderr}")
endif()

file(READ "${FRDP_PROMETHEUS_ALERTS}" alerts)
foreach(expected
        "alert: FRDPSessionManagerDown"
        "expr: frdp_sesmand_reachable == 0"
        "alert: FRDPTextfileScrapeFailed"
        "expr: frdp_exporter_scrape_success == 0"
        "alert: FRDPSessionCapacityHigh"
        "expr: frdp_sessions_max > 0 and (frdp_sessions_active / frdp_sessions_max) > 0.9")
  expect_contains("${alerts}" "${expected}" "Prometheus alerts")
endforeach()
