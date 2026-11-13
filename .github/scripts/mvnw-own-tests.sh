#!/usr/bin/env bash
# mvnw-own-tests.sh <mvnw arguments with -pl MODULES -am test>: the tests of
# MODULES, and only theirs.
#
# With -am, `test` runs the tests of every module Maven builds on the way: each
# database job ran the core's 4,138 tests again - the same tests, with the same
# results as the core job's - and a job that builds the Spring Boot starter ran
# those of some 25 modules, MongoDB's, Oracle's and the AWS module's among
# them, without their servers. So the modules MODULES need are built and
# installed first, without running a test, and then the tests run for MODULES
# alone, against what was just installed.
#
# Without -am or without the test goal the arguments go to mvnw-retry.sh as
# they are.
set -uo pipefail

retry=${MVNW_RETRY:-"$(dirname "$0")/mvnw-retry.sh"}
also_make=0
goal=0
for argument in "$@"; do
  [ "$argument" = "-am" ] && also_make=1
  [ "$argument" = "test" ] && goal=1
done
if [ "$also_make" = 0 ] || [ "$goal" = 0 ]; then
  exec bash "$retry" "$@"
fi

build=()
tests=()
for argument in "$@"; do
  if [ "$argument" = "test" ]; then
    build+=(install -DskipTests)
  else
    build+=("$argument")
  fi
  [ "$argument" = "-am" ] || tests+=("$argument")
done

echo "::group::mvnw-own-tests: what $(printf '%s ' "$@" | grep -o -- '-pl [^ ]*') needs, built without its tests"
bash "$retry" "${build[@]}" || exit $?
echo "::endgroup::"
exec bash "$retry" "${tests[@]}"
