#!/bin/bash

set -e

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
logs=$(find /var/log/exim4/ -name 'mainlog*' -mmin -$mmin -exec ls -tr {} +)

. $base/report.inc

cmd=(
    python3
    $base/report.py
    --contact "$contact_email"
    --org-domain "$organization_domain"
    --date "$report_date"
    $logs
)
if [ -n "$ignore_domains" ]; then
    cmd+=(
        --ignore-domains "$ignore_domains"
    )
fi
if [ -n "$bcc" ]; then
    cmd+=(
        --bcc "$bcc"
    )
fi
cmd+=( "$@" )

"${cmd[@]}"
