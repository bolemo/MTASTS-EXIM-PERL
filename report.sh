#!/bin/bash

set -euo pipefail

base=${0%/*}

# the date, the report should report about
report_date=$(date --date=yesterday --iso)
# minimum modification time of logfiles for $report_date in seconds
min_sec=$(date --date="$report_date - 5min" +%s)
# current time in seconds
now_sec=$(date +%s)
# max logfile mtime age in minutes (for find's -mmin)
mmin=$(( (now_sec - min_sec) / 60 ))
# find all log files, modified since 5min before $report_date, order by time
mapfile -t logs < <(find /var/log/exim4/ -name 'mainlog*' -mmin -$mmin -exec ls -tr {} +)

organization_domain=''
ignore_domains=''
ignore_senders=''
ignore_recipients=''
redis_servers=''
redis_auth=''
. "$base"/report.inc

cmd=(
    python3
    "$base"/report.py
    --contact "$contact_email"
    --org-domain "$organization_domain"
    --date "$report_date"
    "${logs[@]}"
)
if [ -n "$ignore_domains" ]; then
    cmd+=(
        --ignore-domains "$ignore_domains"
    )
fi
if [ -n "$ignore_recipients" ]; then
    cmd+=(
        --ignore-recipients "$ignore_recipients"
    )
fi
if [ -n "$ignore_senders" ]; then
    cmd+=(
        --ignore-senders "$ignore_senders"
    )
fi
if [ -n "$bcc" ]; then
    cmd+=(
        --bcc "$bcc"
    )
fi
if [ -n "$redis_servers" ]; then
    cmd+=(
        --redis-servers "$redis_servers"
    )
fi
if [ -n "$redis_auth" ]; then
    cmd+=(
        --redis-auth "$redis_auth"
    )
fi
cmd+=( "$@" )

"${cmd[@]}"
