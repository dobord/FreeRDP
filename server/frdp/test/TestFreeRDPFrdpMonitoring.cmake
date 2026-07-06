if(NOT DEFINED BASH_EXECUTABLE)
  message(FATAL_ERROR "BASH_EXECUTABLE is not set")
endif()
if(NOT DEFINED FRDP_MONITORING_SCRIPT)
  message(FATAL_ERROR "FRDP_MONITORING_SCRIPT is not set")
endif()
if(NOT DEFINED FRDP_PROMETHEUS_ALERTS)
  message(FATAL_ERROR "FRDP_PROMETHEUS_ALERTS is not set")
endif()
if(NOT DEFINED FRDP_GRAFANA_DASHBOARD)
  message(FATAL_ERROR "FRDP_GRAFANA_DASHBOARD is not set")
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

function(expect_not_contains haystack needle label)
  string(FIND "${haystack}" "${needle}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "${label} unexpectedly contains '${needle}':\n${haystack}")
  endif()
endfunction()

function(expect_matches haystack pattern label)
  if(NOT haystack MATCHES "${pattern}")
    message(FATAL_ERROR "${label} does not match '${pattern}':\n${haystack}")
  endif()
endfunction()

file(WRITE "${fake_frdpctl}" [==[#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $# -ne 3 || ( $1 != status && $1 != list-sessions ) || $2 != --socket ]]; then
	echo "unexpected frdpctl invocation: $*" >&2
	exit 64
fi
case "${FRDP_FAKE_MODE:-ok}" in
	ok)
		printf 'Status: running\nActive sessions: 2\n'
		;;
	detail)
		if [[ $1 == status ]]; then
			printf 'Status: running\nActive sessions: 2\n'
		elif [[ $1 == list-sessions ]]; then
			printf '%-36s  %-20s  %-8s  %-8s\n' SESSION USER DISPLAY PID
			printf '%-36s  %-20s  %-8s  %-8s\n' session-1 alice :20 1001
			printf '%-36s  %-20s  %-8s  %-8s\n' session-2 bob :21 1002
		fi
		;;
	detail-error)
		if [[ $1 == status ]]; then
			printf 'Status: running\nActive sessions: 2\n'
		elif [[ $1 == list-sessions ]]; then
			printf 'detail failure for %s\n' "$3" >&2
			exit 4
		fi
		;;
	missing-count)
		printf 'Status: running\n'
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
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=${fake_bin_dir}:$ENV{PATH}" FRDP_FAKE_MODE=detail
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
        "frdp_exporter_last_scrape_timestamp_seconds{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\"}"
        "frdp_sessions_active{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\"} 2"
        "frdp_sessions_detail_scrape_success{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\"} 1"
        "frdp_sessions_info{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\",session_id=\"session-1\",user=\"alice\",display=\":20\",agent_pid=\"1001\"} 1"
        "frdp_sessions_info{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\",session_id=\"session-2\",user=\"bob\",display=\":21\",agent_pid=\"1002\"} 1"
        "frdp_sessions_max{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\"} 10"
        "frdp_sessions_utilization_ratio{socket=\"/tmp/frdp-\\\"quoted\\\"-socket\"} 0.200000")
  expect_contains("${metrics}" "${expected}" "successful scrape metrics")
endforeach()
expect_matches("${metrics}"
               "frdp_exporter_last_scrape_timestamp_seconds\\{socket=\"/tmp/frdp-\\\\\"quoted\\\\\"-socket\"\\} [1-9][0-9]+"
               "successful scrape metrics")

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
        "frdp_exporter_last_scrape_timestamp_seconds{socket=\"/tmp/frdp-error\"}"
        "frdp_sessions_active{socket=\"/tmp/frdp-error\"} 0"
        "frdp_sessions_detail_scrape_success{socket=\"/tmp/frdp-error\"} 0"
        "frdp_exporter_last_error{socket=\"/tmp/frdp-error\"} 1")
  expect_contains("${metrics}" "${expected}" "failed scrape metrics")
endforeach()
expect_matches("${metrics}"
               "frdp_exporter_last_scrape_timestamp_seconds\\{socket=\"/tmp/frdp-error\"\\} [1-9][0-9]+"
               "failed scrape metrics")
expect_contains("${metrics}" "# Last frdpctl scrape error: cannot reach socket /tmp/frdp-error"
                "failed scrape metrics")

set(malformed_socket "/tmp/frdp-malformed")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=${fake_bin_dir}:$ENV{PATH}" FRDP_FAKE_MODE=missing-count
          "${BASH_EXECUTABLE}" "${FRDP_MONITORING_SCRIPT}" --socket "${malformed_socket}"
          --output "${output_file}" --max-connections 10
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "monitoring malformed scrape case failed: ${stderr}\n${stdout}")
endif()

file(READ "${output_file}" metrics)
foreach(expected
        "frdp_sesmand_reachable{socket=\"/tmp/frdp-malformed\"} 1"
        "frdp_exporter_scrape_success{socket=\"/tmp/frdp-malformed\"} 0"
        "frdp_exporter_last_scrape_timestamp_seconds{socket=\"/tmp/frdp-malformed\"}"
        "frdp_sessions_active{socket=\"/tmp/frdp-malformed\"} 0"
        "frdp_sessions_detail_scrape_success{socket=\"/tmp/frdp-malformed\"} 0"
        "frdp_sessions_max{socket=\"/tmp/frdp-malformed\"} 10"
        "frdp_exporter_last_error{socket=\"/tmp/frdp-malformed\"} 1")
  expect_contains("${metrics}" "${expected}" "malformed scrape metrics")
endforeach()
expect_matches("${metrics}"
               "frdp_exporter_last_scrape_timestamp_seconds\\{socket=\"/tmp/frdp-malformed\"\\} [1-9][0-9]+"
               "malformed scrape metrics")
expect_contains("${metrics}" "# Last frdpctl scrape error: missing active session count"
                "malformed scrape metrics")
expect_not_contains("${metrics}" "frdp_sessions_utilization_ratio{socket=\"/tmp/frdp-malformed\"}"
                    "malformed scrape metrics")

set(detail_error_socket "/tmp/frdp-detail-error")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=${fake_bin_dir}:$ENV{PATH}" FRDP_FAKE_MODE=detail-error
          "${BASH_EXECUTABLE}" "${FRDP_MONITORING_SCRIPT}" --socket "${detail_error_socket}"
          --output "${output_file}" --max-connections 10
  RESULT_VARIABLE result
  OUTPUT_VARIABLE stdout
  ERROR_VARIABLE stderr)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "monitoring detail-error scrape case failed: ${stderr}\n${stdout}")
endif()

file(READ "${output_file}" metrics)
foreach(expected
        "frdp_sesmand_reachable{socket=\"/tmp/frdp-detail-error\"} 1"
        "frdp_exporter_scrape_success{socket=\"/tmp/frdp-detail-error\"} 1"
        "frdp_sessions_active{socket=\"/tmp/frdp-detail-error\"} 2"
        "frdp_sessions_detail_scrape_success{socket=\"/tmp/frdp-detail-error\"} 0"
        "frdp_sessions_utilization_ratio{socket=\"/tmp/frdp-detail-error\"} 0.200000"
        "frdp_exporter_last_error{socket=\"/tmp/frdp-detail-error\"} 1")
  expect_contains("${metrics}" "${expected}" "detail-error scrape metrics")
endforeach()
expect_contains("${metrics}" "# Last frdpctl scrape error: session detail scrape failed: detail failure for /tmp/frdp-detail-error"
                "detail-error scrape metrics")
expect_not_contains("${metrics}" "frdp_sessions_info{socket=\"/tmp/frdp-detail-error\"}"
                    "detail-error scrape metrics")

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
        "alert: FRDPTextfileCollectorStale"
        "expr: time() - frdp_exporter_last_scrape_timestamp_seconds > 300"
        "alert: FRDPSessionCapacityHigh"
        "expr: frdp_sessions_utilization_ratio > 0.9")
  expect_contains("${alerts}" "${expected}" "Prometheus alerts")
endforeach()

file(READ "${FRDP_GRAFANA_DASHBOARD}" dashboard)
foreach(expected
        "\"title\": \"FRDP Server Preview\""
        "\"uid\": \"frdp-server-preview\""
        "\"expr\": \"frdp_sesmand_reachable\""
        "\"expr\": \"frdp_exporter_scrape_success\""
        "\"expr\": \"time() - frdp_exporter_last_scrape_timestamp_seconds\""
        "\"expr\": \"frdp_sessions_active\""
        "\"expr\": \"frdp_sessions_max\""
        "\"expr\": \"frdp_sessions_utilization_ratio\""
        "\"type\": \"prometheus\"")
  expect_contains("${dashboard}" "${expected}" "Grafana dashboard")
endforeach()
