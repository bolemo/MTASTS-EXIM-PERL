#!/usr/bin/python3

import sys
from collections import defaultdict

import argparse
import lmdb
import io
import gzip
import re
import datetime
import json
import email.mime.multipart
import email.mime.text
import email.mime.application
import smtplib
import requests

# convert a datetime object from local time to UTC
# inspired by
# https://stackoverflow.com/questions/4770297/convert-utc-datetime-string-to-local-datetime
def localtz2utc(dt):
    # convert given datetime object to a (local) timestamp
    localts = dt.timestamp()
    # compute offset to utc by
    # difference between given datetime object
    # and a datetime object created as UTC timestamp
    # but from the LOCAL timestamp
    # not that this approach is buggy when local timezone has
    # DST: For timestamps in the interval where DST changes BACKWARD
    # it is impossible to determine if the time is determine if the
    # given time is BEFORE or AFTER the change, e.g.
    # 2023-03-26 02:59:00 can be CET and CEST
    offset = dt - datetime.datetime.utcfromtimestamp(localts)
    # return datetime object adjusted by computed offset
    return dt - offset
def utc2localtz(dt):
    # convert given (utc) datetime object to a LOCAL timestamp
    localts = dt.timestamp()
    # compute offset to utc by
    # difference between given datetime object
    # and a datetime object created as UTC timestamp
    # but from the LOCAL timestamp
    # not that this approach is buggy when local timezone has
    # DST: For timestamps in the interval where DST changes BACKWARD
    # it is impossible to determine if the time is determine if the
    # given time is BEFORE or AFTER the change, e.g.
    # 2023-03-26 02:59:00 can be CET and CEST
    offset = dt - datetime.datetime.utcfromtimestamp(localts)
    # return datetime object adjusted by computed offset
    return dt + offset

def exim_error2mtasts_error(error):
    errors = {
        'a TLS session is required, but the server did not offer TLS support': 'starttls-not-supported',
        # unfortunately exim always reports 'certificate invalid'
        # and does not report if the cert has a host mismatch, expiry or trust issue
        'TLS session: (certificate verification failed): certificate invalid': 'validation-failure',
    }
    if error in errors:
        return errors[error]
    print('Unknown error string "%s"!' % error, file=sys.stderr)
    return 'validation-failure'

def parse_exim_errors(lines):
    errors = defaultdict(int)
    # 2023-03-10 17:58:55 1paeYC-001MTh-0L == measurement@mail-mtasts-rn-plain.measurement.email-security-scans.org R=dnslookup T=remote_smtp_mtasts_enforce defer (-38) H=plaintext.measurement.email-security-scans.org [2a06:d1c0:dead:3::83] I=[2a06:d1c0:dead:2::182] DT=0s: a TLS session is required, but the server did not offer TLS support
    error_re = r'^.+ == (?P<email>\S+) .+ H=(?P<mxhost>\S+) \[(?P<mxip>\S+)\] I=\[(?P<lip>\S+)\].*?: (?P<error>.+)$'
    for line in lines:
        error_match = re.match(error_re, line)
        if not error_match:
            print('Failed to match error line against "%s":\n%s' % (error_re, line), file=sys.stderr)
            continue
        email  = error_match.group('email')
        mxhost = error_match.group('mxhost')
        mxip   = error_match.group('mxip')
        lip    = error_match.group('lip')
        error  = error_match.group('error')
        result_type = exim_error2mtasts_error(error)
        key = (result_type, lip, mxip, mxhost)
        errors[key] += 1
    def key_count2mtasts_details(key, count):
        return {
            "result-type":           key[0],
            "sending-mta-ip":        key[1],
            "receiving-ip":          key[2],
            "receiving-mx-hostname": key[3],
            "failed-session-count":  int(count),
        }
    return [
        key_count2mtasts_details(key, count)
        for key, count in errors.items()
    ]

def gen_report(mtasts):
    report = {
        "organization-name": args.org_name,
        "date-range": {
            "start-datetime": starttime.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "end-datetime":   endtime.strftime('%Y-%m-%dT%H:%M:%SZ'),
        },
        "contact-info": args.contact,
        "report-id": "%s@%s" % (
            localtz2utc( datetime.datetime.now() ).strftime('%Y-%m-%dT%H:%M:%SZ'),
            args.org_name
        ),
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-string": mtasts['policy'].strip().split('\n'),
                    "policy-domain": mtasts['domain'],
                    "mx-host": mtasts['mx'].split(':'),
                },
                "summary": {
                    "total-successful-session-count": len(mtasts['deliveries']),
                    "total-failure-session-count": len(mtasts['errors']),
                },
            },
        ],
    }
    if len(mtasts['errors']) > 0:
        report['policies'][0]['failure-details'] = parse_exim_errors(mtasts['errors'])
    return report

def send_mail(rua, report, fake=True):
    domain = report['policies'][0]['policy']['policy-domain']
    smtp_from = args.contact
    print('Mailing report to %s' % rua)
    smtp_to = [rua] if not fake else []
    if args.bcc:
        smtp_to += args.bcc.split(',')
    
    msg = email.mime.multipart.MIMEMultipart(_subtype='report')
    msg.set_param('report-type', 'tlsrpt')
    msg['Subject'] = 'Report Domain: %s Submitter: %s Report-ID: <%s>' % (
        domain,
        args.org_name,
        report['report-id'],
    )
    msg['To'] = rua
    # XXX:fixme: make this configurable
    msg['From'] = 'SMTP TLS Report by %s <%s>' % (args.org_name, smtp_from)

    body  = 'This is an aggregate TLS report from %s\n' % args.org_name
    body += '\n'
    body += 'For your convenience:\n'
    body += json.dumps(report, indent=4)
    mime_body = email.mime.text.MIMEText(body)
    msg.attach(mime_body)

    report_json = json.dumps(report)
    report_gz = gzip.compress(report_json.encode())
    filename = '%s!%s!%s!%s!001.json.gz' % (
        args.org_name,
        domain,
        int(starttime.timestamp()),
        int(endtime.timestamp()),
    )
    mime_report = email.mime.application.MIMEApplication(report_gz, _subtype='tlsrpt+gzip')
    mime_report.add_header('content-disposition', 'attachment', filename=filename)
    msg.attach(mime_report)

    smtp_body = msg.as_string()
    if args.dry_run:
        print(dsep)
        print(smtp_body)
        print(dsep)
        return
    with smtplib.SMTP(host='localhost') as smtp:
        failed_recipients = smtp.sendmail(smtp_from, smtp_to, msg.as_string())
        if len(failed_recipients) > 0:
            print('Failed to send mail to: %s' % failed_recipients, file=sys.stderr)
    
def mail_report(rua, report):
    if args.no_mails:
        return
    # strip 'mailto:' prefix
    rua_email = rua[7:]
    send_mail(rua_email, report)
    return

# HTTP debugging
# import logging
# # These two lines enable debugging at httplib level (requests->urllib3->http.client)
# # You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# # The only thing missing will be the response.body which is not logged.
# import http.client as http_client
# http_client.HTTPConnection.debuglevel = 1
# # You must initialize logging, otherwise you'll not see debug output.
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)

def post_report(rua, report):
    if args.no_posts:
        return
    print('POSTing report to %s' % rua)
    headers =  {'Content-Type': 'application/tlsrpt+json'}
    if args.dry_run:
        print(dsep)
        print('POST %s headers=%s\n%s\n' % (rua, headers, json.dumps(report, indent=4)))
        print(dsep)
        return
    send_mail('POST@%s' % re.sub(r'[/?&]', '.', rua[8:]), report, fake=True)
    try:
        response = requests.post(rua, json=report, headers=headers)
    except requests.exceptions.ConnectionError as e:
        print('POST to "%s" failed with ConnectionError: %s' % (rua, e), file=sys.stderr)
        return
    if not response.ok:
        print('POST to "%s" failed with %s %s: %s' % (rua, response.status_code, response.reason, response.text), file=sys.stderr)
        return
    print(response)
    print(response.content.decode())
    return
'''
POST to "https://tlsrpt.azurewebsites.net/report" failed with 400 Bad Request: The content type should either be application/tlsrpt+gzip or application/tlsrpt+json
(and no encoding!)
POST to "https://tlsrpt.azurewebsites.net/report" failed with 400 Bad Request: Start date time shall be 00:00 of a day
POST to "https://tlsrpt.azurewebsites.net/report" failed with 400 Bad Request: Requests from a same IP address and sender organization are not allowed in 24 hours
'''

def send_report(mtasts):
    rua = mtasts['report']
    try:
        method, _ = rua.split(':', maxsplit=1)
    except ValueError:
        # workaround for buggy db data before substr(,7) fix
        if rua.startswith('/'):
            method = 'https'
            rua = 'https:/'+rua
        else:
            method = 'mailto'
            rua = 'mailto:'+rua
    rua_methods = dict(
        mailto=mail_report,
        https=post_report,
    )
    if method not in rua_methods:
        print('Unsupported rua method "%s" in rua "%s"!' % (method, rua))
        return
    rua_methods[method](rua, gen_report(mtasts))



# ARGUMENTS
default_lmdb = '/var/spool/exim4/lmdb2/'
default_org_name = 'SnakeOil'
default_contact = 'smtp-tls-reports@invalid'
yesterday = datetime.date.today() - datetime.timedelta(days=1)
parser = argparse.ArgumentParser(description='MTA-STS report generator')
parser.add_argument('--lmdb',     type=str, help="path to mta-lmdb.pl's lmdb database", default=default_lmdb)
parser.add_argument('--org-name', type=str, help='orginization name in reports',        default=default_org_name)
parser.add_argument('--contact',  type=str, help='contact info in reports',             default=default_contact)
parser.add_argument('--date',     type=str, help='ISO date of report (def: yesterday)', default=str(yesterday))
parser.add_argument('--bcc',      type=str, help='BCC for send mails, comma seperated')
parser.add_argument('--dry-run',  action='store_true', help='do not MAIL or POST reports')
parser.add_argument('--no-mails', action='store_true', help='do not MAIL reports')
parser.add_argument('--no-posts', action='store_true', help='do not POST reports')
parser.add_argument('logfiles',   type=str, help='exim log files', nargs='+')
args = parser.parse_args()
startdate = datetime.date.fromisoformat(args.date)
starttime = datetime.datetime.fromisoformat(startdate.isoformat())
endtime   = starttime + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
dsep = '='*200


# initialize the fields of out mtadb data
mtadb = defaultdict(
    lambda: dict(
        id=None,
        domain=None,
        policy='not stored',
        mode=None,
        mx=[],
        report=None,
        expire=None,
        needsreport=False,
        deliveries=[],
        errors=[],
    )
)

# open LMDB database
env = lmdb.open(args.lmdb, max_dbs=10)
db = env.open_db()
# iterate over all entries
with env.begin() as txn:
    # the very first entry is the name of the db and the value is not decodable, so we skip it
    for key, value in list(txn.cursor(db=db))[1:]:
        k, v = key.decode(), value.decode()
        domain, attr = k.split(':', maxsplit=1)
        # store the domain as part of the 'mtasts' struct
        mtadb[domain]['domain'] = domain
        # store all values in the corresponding attr
        mtadb[domain][attr] = v


# generate a regex from all domains
domains_re = r'|'.join( [ re.escape(domain) for domain in mtadb.keys() ] )
exim_delivery_re = r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .+ (?P<delivered>[=-][>=]) \S+@(?P<domain>' + domains_re + r') .+ H=(?P<mxhost>\S+) .+$'
# read the exim logfile
def match_mx(host, mtadbmx):
    mx_list = mtadbmx.split(':')
    if host in mx_list:
        return True
    parts = host.split('.')
    parts[0] = '*'
    glob_host = '.'.join(parts)
    if glob_host in mx_list:
        return True
    return False
for logfile in args.logfiles:
    file_open = gzip.open if logfile.endswith('.gz') else io.open
    with file_open(logfile, mode='rt', encoding='utf-8') as f:
        for line in f.readlines():
            delivery_match = re.match(exim_delivery_re, line)
            # skip all lines, that are not delivery/defer messages
            if not delivery_match:
                continue
            # skip all retry time defers
            if 'retry time not reached' in line:
                continue
            localdt = datetime.datetime.fromisoformat( delivery_match.group('ts') )
            utcdt = localtz2utc(localdt)
            if starttime > utcdt or endtime < utcdt:
                print('Ignoring wrong time: %s' % line.strip(), file=sys.stderr)
                continue
            line = line.strip()
            # check if successful delivery or defer
            delivered = delivery_match.group('delivered').endswith('>')
            # get the matched domain
            domain = delivery_match.group('domain')
            # get the used MX host
            mxhost = delivery_match.group('mxhost')
            # flag domain needs reporting
            mtadb[domain]['needsreport'] = True
            # store log line in 'deliveries' resp. 'errors'
            if delivered:
                mtadb[domain]['deliveries'].append(line)
                continue
            mtadb[domain]['errors'].append(line)
            # check if mx hostnames do no match this delivery line
            if not match_mx(mxhost, mtadb[domain]['mx']):
                print('Warning: Host "%s" must not be used to deliver to domain "%s" according to policy:\n%s' % (mxhost, domain, mtadb[domain]['policy']), file=sys.stderr)


# iterate over all domains
for domain, mtasts in mtadb.items():
    # skip domains, that do not need a report (no logs found)
    if not mtasts['needsreport']:
        continue
    # send report otherwise
    send_report(mtasts)
