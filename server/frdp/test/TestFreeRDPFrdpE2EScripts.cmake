if(NOT DEFINED BASH_EXECUTABLE)
  message(FATAL_ERROR "BASH_EXECUTABLE is not set")
endif()
if(NOT DEFINED FRDP_E2E_DIR)
  message(FATAL_ERROR "FRDP_E2E_DIR is not set")
endif()

function(expect_file path)
  if(NOT EXISTS "${path}")
    message(FATAL_ERROR "expected E2E fixture is missing: ${path}")
  endif()
endfunction()

function(expect_contains haystack needle label)
  string(FIND "${haystack}" "${needle}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "${label} is missing '${needle}':\n${haystack}")
  endif()
endfunction()

foreach(script
        run.sh
        TestRunner.sh
        scripts/frdpd-entrypoint.sh
        scripts/frdpd-healthcheck.sh
        scripts/freeipa-ready.sh
        scripts/rdp-load-probe.sh
        scripts/rdp-probe.sh
        scripts/rdp-protocol-regression.sh
        scripts/rdp-session-smoke.sh
        scripts/samba-entrypoint.sh)
  set(script_path "${FRDP_E2E_DIR}/${script}")
  expect_file("${script_path}")
  execute_process(
    COMMAND "${BASH_EXECUTABLE}" -n "${script_path}"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE stdout
    ERROR_VARIABLE stderr)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "bash syntax check failed for ${script}: ${stderr}\n${stdout}")
  endif()
endforeach()

execute_process(
  COMMAND "${BASH_EXECUTABLE}" "${FRDP_E2E_DIR}/TestRunner.sh"
  RESULT_VARIABLE runner_test_result
  OUTPUT_VARIABLE runner_test_stdout
  ERROR_VARIABLE runner_test_stderr)
if(NOT runner_test_result EQUAL 0)
  message(FATAL_ERROR
    "E2E runner behavior test failed: ${runner_test_stderr}\n${runner_test_stdout}")
endif()

foreach(fixture
        .env.example
        Dockerfile
        Dockerfile.freeipa
        Dockerfile.samba
        frdpd.toml
        pam/frdpd-local
        pam/frdpd-sssd)
  expect_file("${FRDP_E2E_DIR}/${fixture}")
endforeach()

set(compose_file "${FRDP_E2E_DIR}/compose.yaml")
expect_file("${compose_file}")
file(READ "${compose_file}" compose)

foreach(expected
        "component-tests:"
        "rdp-client-local:"
        "samba-dc:"
        "rdp-client-samba:"
        "freeipa:"
        "rdp-client-freeipa:"
        "profiles: [\"component\"]"
        "profiles: [\"local\"]"
        "profiles: [\"samba\"]"
        "profiles: [\"freeipa\"]"
        "FRDP_TEST_GROUP: \${FRDP_TEST_GROUP:-rdp-users}"
        "FRDP_FREEIPA_ENROLL_PASSWORD: \${FRDP_FREEIPA_ENROLL_PASSWORD:-IpaEnrollPassw0rd!}"
        "FRDP_DENY_LABEL: policy-denied"
        "WITH_FREEIPA_CLIENT: ON"
        "samba-tool group listmembers"
        "grep -Fxq")
  expect_contains("${compose}" "${expected}" "E2E compose file")
endforeach()

file(READ "${FRDP_E2E_DIR}/Dockerfile" frdp_dockerfile)
foreach(expected
        "ARG WITH_FREEIPA_CLIENT=OFF"
        "if [ \"$WITH_FREEIPA_CLIENT\" = ON ]; then"
        "apt-get install -y --no-install-recommends freeipa-client")
  expect_contains("${frdp_dockerfile}" "${expected}" "FRDP E2E image")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/samba-entrypoint.sh" samba_entrypoint)
foreach(expected
        "FRDP_TEST_GROUP:-rdp-users"
        "samba-tool group add"
        "samba-tool group addmembers"
        "samba-tool group listmembers")
  expect_contains("${samba_entrypoint}" "${expected}" "Samba entrypoint")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/frdpd-entrypoint.sh" frdpd_entrypoint)
foreach(expected
        "wait_supplementary_group"
        "getent group \"$group\""
        "id -G \"$user\""
        "SSSD resolved supplementary group"
        "SSSD did not resolve supplementary group")
  expect_contains("${frdpd_entrypoint}" "${expected}" "frdpd entrypoint")
endforeach()

foreach(expected
        "ipa-client-install"
        "id_provider = ipa"
        "access_provider = ipa"
        "krb5_validate = true"
        "host/$host@$realm"
        "FreeIPA HBAC did not allow the test user"
        "pam_acct_mgmt: Permission denied"
        "FreeIPA HBAC did not deny the policy-test user")
  expect_contains("${frdpd_entrypoint}" "${expected}" "frdpd FreeIPA enrollment")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/freeipa-ready.sh" freeipa_ready)
foreach(expected
        "ipa host-add"
        "ipa hbacrule-add-user"
        "ipa hbacrule-add-host"
        "ipa hbacrule-add-service"
        "ipa hbacrule-disable allow_all")
  expect_contains("${freeipa_ready}" "${expected}" "FreeIPA seed policy")
endforeach()

file(READ "${FRDP_E2E_DIR}/run.sh" runner)
foreach(expected
        "component)"
        "local)"
        "samba)"
        "freeipa)"
        "all)"
        "FRDP_E2E_ARTIFACTS"
        "FRDP_E2E_PROFILE_TIMEOUT"
        "FRDP_E2E_REPETITIONS"
        "profile_timeout"
        "repetitions"
        "command -v git"
        "command -v tar"
        "command -v docker"
        "docker compose version"
        "command -v timeout"
        "timeout \"\${profile_timeout}s\""
        "up --no-build"
        "--profile \"$profile\" down --volumes --remove-orphans"
        "snapshot_excluded_paths"
        "\${root#\"$repo_root/\"}/artifacts"
        "snapshot_excludes"
        "\${artifacts#\"$repo_root/\"}"
        "mktemp \"\${TMPDIR:-/tmp}/frdp-source."
        "source snapshot contains excluded path"
        "tar -tzf \"$source_archive\""
        "exceeded FRDP_E2E_PROFILE_TIMEOUT"
        "compose-config.yaml"
        "must be a dedicated non-root directory named artifacts"
        "rm -rf -- \"\${artifacts:?}/$profile\""
        "repetition-summary.txt"
        "incomplete-run-$repeat_current"
        "finalize_repeated_artifacts"
        "transfer_artifact_tree"
        "refresh_repeat_completed"
        "repeat_finalizing"
        "active_profile"
        "saved_status == \"$status\""
        "set -Eeuo pipefail"
        "run_profile_once"
        "validate_rdp_auth_artifacts"
        "server-auth.log"
        "expected 3 PAM accepts and 2 PAM denials"
        "one NTLM proof rejection and two denied-user PAM denials"
        "proof identity does not match the delegated credentials"
        "profile freeipa is missing joined-host evidence"
        "Access granted by HBAC rule [frdpd-allow]"
        "Access denied by HBAC rules"
        "container-inspect")
  expect_contains("${runner}" "${expected}" "E2E runner")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/rdp-probe.sh" rdp_probe)
foreach(expected
        "FRDP_E2E_TIMEOUT"
        "FRDP_AUTH_TIMEOUT"
        "FRDP_DENY_LABEL"
        "positive_integer \"$FRDP_E2E_TIMEOUT\""
        "positive_integer \"$FRDP_AUTH_TIMEOUT\""
        "command -v timeout"
        "command -v xvfb-run"
        "command -v Xvfb"
        "command -v xwd"
        "command -v xclip"
        "command -v ps"
        "command -v nc"
        "command -v find"
        "command -v frdpctl"
        "timeout \"\${FRDP_AUTH_TIMEOUT}s\""
        "-auto-reconnect"
        "frdpctl list-sessions --socket"
        "assert_no_managed_sessions"
        "session-list-after-auth-\${label}.txt"
        "session-runtime-after-auth-\${label}.txt"
        "left managed session runtime artifacts"
        "cleanup_auth_only_session"
        "session-list-after-auth-valid-cleanup.txt"
        "valid auth-only managed session was cleaned"
        "rdp-reconnect.log"
        "session-list-reconnected.txt"
        "session-list-reconnected-held.txt"
        "session_identity_is_exclusively_active"
        "process_is_running"
        "managed RDP session reattached with stable id/display/PID"
        "client-to-server Unicode clipboard transfer passed"
        "server-to-client Unicode clipboard transfer passed"
        "session-list-after-reconnect.txt")
  expect_contains("${rdp_probe}" "${expected}" "E2E RDP probe script")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/rdp-load-probe.sh" load_probe)
foreach(expected
        "FRDP_LOAD_CONCURRENCY"
        "FRDP_LOAD_ITERATIONS"
        "FRDP_LOAD_TIMEOUT"
        "command -v timeout"
        "command -v xvfb-run"
        "command -v nc"
        "timeout \"\${FRDP_LOAD_TIMEOUT}s\"")
  expect_contains("${load_probe}" "${expected}" "E2E load probe script")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/rdp-protocol-regression.sh" protocol_probe)
foreach(expected
        "FRDP_PROTOCOL_TIMEOUT"
        "command -v timeout"
        "command -v xvfb-run"
        "command -v nc"
        "timeout \"\${FRDP_PROTOCOL_TIMEOUT}s\"")
  expect_contains("${protocol_probe}" "${expected}" "E2E protocol regression script")
endforeach()

file(READ "${FRDP_E2E_DIR}/scripts/rdp-session-smoke.sh" session_smoke)
foreach(expected
        "FRDP_SESSION_TIMEOUT"
        "FRDP_SESSION_HOLD_SECONDS"
        "command -v Xvfb"
        "command -v xdpyinfo"
        "command -v xwd"
        "command -v ps"
        "command -v nc"
        "command -v frdpctl"
        "allocate_display"
        "xdpyinfo -display \"$display_name\""
        "frdpctl status --socket"
        "frdpctl list-sessions --socket"
        "list_status=$?"
        "awk -v id=\"$session_id\""
        "xwd -display \"$display_name\" -root"
        "managed RDP session detached after client disconnect"
        "rdp-reconnect.log"
        "session-list-reconnected.txt"
        "session-list-reconnected-held.txt"
        "session_identity_is_exclusively_active"
        "process_is_running"
        "managed RDP session reattached with stable id/display/PID"
        "session-list-after-reconnect.txt"
        "frdpctl kill-session \"$session_id\" --socket"
        "managed RDP session was cleaned after explicit kill-session")
  expect_contains("${session_smoke}" "${expected}" "E2E session smoke script")
endforeach()

get_filename_component(frdp_repo_root "${FRDP_E2E_DIR}/../../../.." ABSOLUTE)
file(READ "${frdp_repo_root}/.github/workflows/frdpd-compose.yml" frdp_workflow)

function(expect_workflow_job_contains job next_job needle)
  set(job_marker "\n  ${job}:\n")
  string(FIND "${frdp_workflow}" "${job_marker}" job_start)
  if(job_start EQUAL -1)
    message(FATAL_ERROR "FRDP workflow is missing the ${job} job")
  endif()
  if(next_job)
    string(FIND "${frdp_workflow}" "\n  ${next_job}:\n" job_end)
    if(job_end EQUAL -1 OR job_end LESS_EQUAL job_start)
      message(FATAL_ERROR "FRDP workflow has an invalid ${job}/${next_job} job boundary")
    endif()
  else()
    string(LENGTH "${frdp_workflow}" job_end)
  endif()
  math(EXPR job_length "${job_end} - ${job_start}")
  string(SUBSTRING "${frdp_workflow}" ${job_start} ${job_length} job_block)
  expect_contains("${job_block}" "${needle}" "FRDP ${job} workflow job")
endfunction()

function(expect_workflow_job_ordered job next_job)
  set(job_marker "\n  ${job}:\n")
  string(FIND "${frdp_workflow}" "${job_marker}" job_start)
  string(FIND "${frdp_workflow}" "\n  ${next_job}:\n" job_end)
  if(job_start EQUAL -1 OR job_end EQUAL -1 OR job_end LESS_EQUAL job_start)
    message(FATAL_ERROR "FRDP workflow has an invalid ${job}/${next_job} job boundary")
  endif()
  math(EXPR job_length "${job_end} - ${job_start}")
  string(SUBSTRING "${frdp_workflow}" ${job_start} ${job_length} job_block)
  set(previous_position -1)
  foreach(needle IN LISTS ARGN)
    string(FIND "${job_block}" "${needle}" position)
    if(position EQUAL -1)
      message(FATAL_ERROR "FRDP ${job} workflow job is missing '${needle}'")
    endif()
    if(position LESS_EQUAL previous_position)
      message(FATAL_ERROR
        "FRDP ${job} workflow job has '${needle}' outside the required evidence order")
    endif()
    set(previous_position ${position})
  endforeach()
endfunction()

set(provider_repeat_expression
    "FRDP_E2E_REPETITIONS: \${{ github.event_name == 'schedule' && '2' || '1' }}")
foreach(expected
        "Build in clean Ubuntu from declared dependencies"
        "git archive --format=tar"
        "-v \"$source_tar:/tmp/frdpd-source.tar:ro\""
        "mk-build-deps --install --remove"
        "dpkg-buildpackage -uc -us -b -j2"
        "lintian --fail-on error --display-info --pedantic"
        "lintian_status=\${PIPESTATUS[0]}"
        "tee /out/frdpd_lintian.txt"
        "exit \"$lintian_status\""
        "build_artifacts=\"$artifacts/build\""
        "test -s \"$build_artifacts/frdpd_lintian.txt\""
        "test ! -e \"$artifacts/control/shlibs\""
        "test ! -e \"$artifacts/control/triggers\""
        "forbidden='(^|, )(libavcodec|libavformat|libavutil|libswscale|liburiparser|libxkbfile|libfreerdp|libwinpr)'"
        "ubuntu:24.04 bash -lc"
        "dpkg -V frdpd"
        "grep -q \"/lib/$FRDP_MULTIARCH/frdpd/libwinpr3.so.3\""
        "grep -q \"/lib/$FRDP_MULTIARCH/frdpd/libfreerdp3.so.3\""
        "winpr-hash -u alice --password-stdin"
        "apt-get purge -y frdpd"
        "test ! -e /usr/bin/frdpd")
  expect_workflow_job_contains("deb" "rpm" "${expected}")
endforeach()
expect_workflow_job_ordered("deb" "rpm"
  "output_dir=\"$FRDP_E2E_ARTIFACTS/deb/build\""
  "set +e"
  "lintian --fail-on error --display-info --pedantic"
  "lintian_status=\${PIPESTATUS[0]}"
  "set -e"
  "cp /build/frdpd_*.deb"
  "exit \"$lintian_status\""
  "if: always()"
  "uses: actions/upload-artifact@v4")
foreach(expected
        "container: fedora:42"
        "dnf -y builddep packaging/rpm/frdpd.spec"
        "rpmbuild -ba packaging/rpm/frdpd.spec"
        "dnf -y install \"$rpm_path\""
        "rpm -V frdpd"
        "rpm -qp --provides \"$rpm_path\""
        "private_abi='^(libfreerdp3|libfreerdp-server3|libwinpr3|libwinpr-tools3)"
        "grep -q '/lib64/frdpd/libwinpr3.so.3'"
        "grep -q '/lib64/frdpd/libfreerdp3.so.3'")
  expect_workflow_job_contains("rpm" "fuzz" "${expected}")
endforeach()

file(READ "${frdp_repo_root}/debian/control" frdp_debian_control)
foreach(expected "libicu-dev")
  expect_contains("${frdp_debian_control}" "${expected}" "FRDP Debian control")
endforeach()

set(frdp_debian_copyright "${frdp_repo_root}/debian/copyright")
expect_file("${frdp_debian_copyright}")
file(READ "${frdp_debian_copyright}" frdp_debian_copyright_text)
foreach(expected
        "copyright-format/1.0/"
        "complete source-package copyright audit remains required"
        "Files: CMakeLists.txt"
        "License: Apache-2.0"
        "License: BSD-3-clause"
        "License: BSL-1.0"
        "License: Expat"
        "License: HPND-sell-variant"
        "License: Zlib"
        "License: public-domain"
        "/usr/share/common-licenses/Apache-2.0")
  expect_contains("${frdp_debian_copyright_text}" "${expected}" "FRDP Debian copyright")
endforeach()
foreach(unexpected
        "libavcodec-dev"
        "libavformat-dev"
        "libavutil-dev"
        "libswscale-dev"
        "libjpeg-dev"
        "libpng-dev")
  string(FIND "${frdp_debian_control}" "${unexpected}" deb_dependency_found)
  if(NOT deb_dependency_found EQUAL -1)
    message(FATAL_ERROR "FRDP Debian control retains disabled dependency ${unexpected}")
  endif()
endforeach()

file(READ "${frdp_repo_root}/debian/rules" frdp_debian_rules)
foreach(expected
        "-DWITH_FRDPD=ON"
        "-DWITH_FFMPEG=OFF"
        "-DWITH_SWSCALE=OFF"
        "-DWITH_URIPARSER=OFF"
        "-DWITH_JPEG=OFF"
        "-DWINPR_UTILS_IMAGE_PNG=OFF"
        "-DWINPR_UTILS_IMAGE_JPEG=OFF"
        "-DCMAKE_INSTALL_LIBDIR=lib/$(DEB_HOST_MULTIARCH)/frdpd"
        "override_dh_makeshlibs:"
        "dh_makeshlibs -Xusr/lib/$(DEB_HOST_MULTIARCH)/frdpd/")
  expect_contains("${frdp_debian_rules}" "${expected}" "FRDP Debian rules")
endforeach()
expect_workflow_job_contains("samba" "freeipa" "${provider_repeat_expression}")
expect_workflow_job_contains("freeipa" "" "${provider_repeat_expression}")
string(REGEX MATCHALL "FRDP_E2E_REPETITIONS:" provider_repeat_settings "${frdp_workflow}")
list(LENGTH provider_repeat_settings provider_repeat_count)
if(NOT provider_repeat_count EQUAL 2)
  message(FATAL_ERROR
          "expected exactly two provider repetition settings, found ${provider_repeat_count}")
endif()

file(READ "${frdp_repo_root}/packaging/rpm/frdpd.spec" frdp_rpm_spec)
foreach(expected
        "BuildRequires: pkgconf-pkg-config, zlib-devel, cjson-devel, libicu-devel"
        "BuildRequires: libjpeg-turbo-devel, libpng-devel"
        "%global __provides_exclude_from ^%{_libdir}/frdpd/.*$"
        "%global __requires_exclude ^(libfreerdp3|libfreerdp-server3|libwinpr3|libwinpr-tools3)"
        "-DWITH_FRDPD=ON"
        "-DWITH_CLIENT_COMMON=OFF"
        "-DWITH_CLIENT_CHANNELS=OFF"
        "-DCMAKE_INSTALL_SYSCONFDIR=%{_sysconfdir}"
        "-DCMAKE_INSTALL_LIBDIR=%{_lib}/frdpd"
        "%cmake_build --target winpr-tools winpr-hash"
        "%cmake_install --component libraries"
        "%{_libdir}/frdpd/lib*.so*"
        "/usr/bin/winpr-hash"
        "%{_datadir}/frdpd/monitoring/frdpd-grafana-dashboard.json")
  expect_contains("${frdp_rpm_spec}" "${expected}" "FRDP RPM spec")
endforeach()
string(FIND "${frdp_rpm_spec}" "-DWITH_FRDPD_NTLM=OFF" rpm_ntlm_disabled)
if(NOT rpm_ntlm_disabled EQUAL -1)
  message(FATAL_ERROR "FRDP RPM spec disables default-on NTLM support")
endif()
