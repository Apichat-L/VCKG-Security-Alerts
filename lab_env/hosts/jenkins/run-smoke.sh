#!/bin/sh
# Run the Jenkins job `api-smoke` through Jenkins' own REST API and wait for its result.
# Exit 0 if the build succeeds (Jenkins can reach the API and Gitea), 1 otherwise. Used by lab_env/eval/checks.csv.
set -u
J=http://localhost:8080
JOB=$J/job/api-smoke
JAR=/tmp/jenkins-cookies
before=$(curl -fs "$JOB/lastBuild/buildNumber" 2>/dev/null || echo 0)
crumb=$(curl -fs -c "$JAR" "$J/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)" 2>/dev/null || true)
curl -fs -b "$JAR" ${crumb:+-H "$crumb"} -X POST "$JOB/build" >/dev/null || { echo "cannot trigger api-smoke"; exit 1; }
i=0
while [ $i -lt 30 ]; do
    i=$((i + 1))
    sleep 2
    n=$(curl -fs "$JOB/lastBuild/buildNumber" 2>/dev/null || echo 0)
    [ "$n" -gt "$before" ] || continue
    result=$(curl -fs "$JOB/lastBuild/api/xml?xpath=//result/text()" 2>/dev/null || true)
    case "$result" in
        SUCCESS) echo "api-smoke #$n SUCCESS"; exit 0 ;;
        FAILURE|ABORTED|UNSTABLE) echo "api-smoke #$n $result"; exit 1 ;;
    esac
done
echo "api-smoke did not finish"
exit 1
