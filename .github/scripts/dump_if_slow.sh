#!/usr/bin/env bash
# Diagnostics only - not for main. Runs the command; if it is still running
# after $1 minutes, writes a thread dump of every surefire test JVM as a
# GitHub annotation (readable through the API, unlike the log), then stops
# the command so the job ends instead of hanging until it is cancelled.
limit="$1"; shift
"$@" &
pid=$!
(
  sleep $((limit * 60))
  if kill -0 "$pid" 2>/dev/null; then
    echo "::warning title=still running after ${limit} min::dumping the test JVMs"
    for jvm in $(jcmd -l 2>/dev/null | grep -i surefire | awk '{print $1}'); do
      dump=$(jcmd "$jvm" Thread.print 2>/dev/null | grep -v '^\s*- locked\|^\s*- parking\|^$' | head -c 60000)
      [ -z "$dump" ] && continue
      enc=$(printf '%s' "$dump" | sed -e 's/%/%25/g' -e 's/\r/%0D/g' | awk 'BEGIN{ORS="%0A"} {print}')
      echo "::warning title=thread dump of surefire JVM ${jvm}::${enc}"
    done
    pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null
  fi
) &
wait "$pid"
