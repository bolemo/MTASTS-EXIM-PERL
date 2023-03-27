#!/usr/bin/python3

import sys
from collections import defaultdict

import argparse
import lmdb
import dns.resolver
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

def warn(msg):
    print(msg, file=sys.stderr)
    return

# initialize the fields of out tlsrpt data
tlsrpt_struct = lambda: dict(
    id=None,
    domain=None,
    policy='not stored',
    policy_type='sts',
    mode=None,
    mx=[],
    report=None,
    expire=None,
    needsreport=False,
    logs=[],
    deliveries=[],
    errors=[],
)
tlsrpt_data = defaultdict(tlsrpt_struct)

# resolve a given qname+rdtype and return a set of resource records or an empty set on error
def dns_resolve_rrset(qname, rdtype):
    try:
        answer = dns.resolver.resolve(qname, rdtype, search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return set()
    return { rr.to_text() for rr in answer }

# returns rua value of domain's DNS TLSRPT record or None if no such record found
def get_tlsrpt_rua(domain):
    for record in dns_resolve_rrset('_smtp._tls.%s' % domain, 'TXT'):
        # record='"v=TLSRPTv1; rua=email@domain.tld"'
        if not record.startswith('"v=TLSRPTv1;'):
            continue
        tlsrpt = record[12:-1].strip()
        if re.match('.*[ ;]', tlsrpt):
            warn('Illegal TLSRPT record: %s' % record)
            continue
        # "rua=..."
        return tlsrpt[4:]
    return None

# returns a dict of mx: tlsa_rrset of domain for all MX with valid TLSA records
def get_tlsa_mx(domain):
    tlsa_mx = {}
    for mx_record in dns_resolve_rrset(domain, 'MX'):
        prio, mx = mx_record.split()
        tlsa = [
            '_25._tcp.%s IN TLSA %s' % (mx, tlsa_record)
            for tlsa_record in dns_resolve_rrset('_25._tcp.%s' % mx, 'TLSA')
        ]
        if not len(tlsa):
            continue
        # remove trailing '.' from mx to allow matching in mail logs
        while mx.endswith('.'):
            mx = mx[:-1]
        tlsa_mx[mx] = ';'.join(tlsa)
    return tlsa_mx

# generate tlsrpt struct for a non-MTA-STS domain
def non_mtasts_domain(domain):
    tlsrpt = tlsrpt_struct()
    tlsrpt.update(dict(
        domain = domain,
        policy = 'no-policy-found',
        policy_type = 'no-policy-found',
    ))
    rua = get_tlsrpt_rua(domain)
    if rua is None:
        # no TLSRPT record: none policy
        tlsrpt['policy_type'] = 'none'
        return tlsrpt
    tlsrpt['report'] = rua
    tlsa_mx = get_tlsa_mx(domain)
    if len(tlsa_mx) > 0:
        # TLSA records found, DANE in use
        tlsrpt.update(dict(
            policy_type = 'tlsa',
            policy = ';'.join(tlsa_mx.values()),
            mx = list(tlsa_mx.keys()),
        ))
    return tlsrpt

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

def exim_error2tlsrpt_error(error):
    errors = {
        # https://easydmarc.com/blog/de/simple-mail-transfer-protocol-smtp-tls-berichterstattung/
        'a TLS session is required, but the server did not offer TLS support': 'starttls-not-supported',
        # unfortunately exim always reports 'certificate invalid'
        # and does not report if the cert has a host mismatch, expiry or trust issue
        'TLS session: (certificate verification failed): certificate invalid': 'validation-failure',
        'TLS session: (certificate verification failed): Verification failed. The certificate differs.': 'validation-failure',
    }
    if error in errors:
        return errors[error]
    warn('Unknown error string "%s"!' % error)
    return 'validation-failure'

def parse_exim_errors(lines):
    errors = defaultdict(int)
    # 2023-03-10 17:58:55 1paeYC-001MTh-0L == measurement@mail-mtasts-rn-plain.measurement.email-security-scans.org R=dnslookup T=remote_smtp_mtasts_enforce defer (-38) H=plaintext.measurement.email-security-scans.org [2a06:d1c0:dead:3::83] I=[2a06:d1c0:dead:2::182] DT=0s: a TLS session is required, but the server did not offer TLS support
    error_re = r'^.+ == (?P<email>\S+) .+ H=(?P<mxhost>\S+) \[(?P<mxip>\S+)\] I=\[(?P<lip>\S+)\].*?: (?P<error>.+)$'
    for line in lines:
        error_match = re.match(error_re, line)
        if not error_match:
            warn('Failed to match error line against "%s":\n%s' % (error_re, line))
            continue
        email  = error_match.group('email')
        mxhost = error_match.group('mxhost')
        mxip   = error_match.group('mxip')
        lip    = error_match.group('lip')
        error  = error_match.group('error')
        result_type = exim_error2tlsrpt_error(error)
        key = (result_type, lip, mxip, mxhost)
        errors[key] += 1
    return [
        {
            "result-type":           key[0],
            "sending-mta-ip":        key[1],
            "receiving-ip":          key[2],
            "receiving-mx-hostname": key[3],
            "failed-session-count":  int(count),
        }
        for key, count in errors.items()
    ]

def gen_report(tlsrpt):
    policy = {
        "policy-type": tlsrpt['policy_type'],
        "policy-domain": tlsrpt['domain'],
    }
    if tlsrpt['policy_type'] in ['sts', 'tlsa']:
        policy.update({
            "policy-string": tlsrpt['policy'].strip().split('\n'),
            "mx-host":       tlsrpt['mx'],
        })
    report = {
        "organization-name": args.org_name,
        "date-range": {
            "start-datetime": starttime.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "end-datetime":   endtime.strftime('%Y-%m-%dT%H:%M:%SZ'),
        },
        "contact-info": args.contact,
        "report-id": "%s@%s" % (
            localtz2utc( datetime.datetime.now() ).strftime('%Y-%m-%dT%H:%M:%SZ'),
            args.org_domain
        ),
        "policies": [
            {
                "policy": policy,
                "summary": {
                    "total-successful-session-count": len(tlsrpt['deliveries']),
                    "total-failure-session-count": len(tlsrpt['errors']),
                },
            },
        ],
    }
    if len(tlsrpt['errors']) > 0:
        report['policies'][0]['failure-details'] = parse_exim_errors(tlsrpt['errors'])
    return report

def send_mail(rua, report, fake=False):
    domain = report['policies'][0]['policy']['policy-domain']
    smtp_from = args.contact
    print('Mailing report to %s (domain:%s)' % (rua, domain))
    smtp_to = [rua] if not fake else []
    if args.bcc:
        smtp_to += args.bcc.split(',')
    
    msg = email.mime.multipart.MIMEMultipart(_subtype='report')
    msg.set_param('report-type', 'tlsrpt')
    msg['Subject'] = 'Report Domain: %s Submitter: %s Report-ID: <%s>' % (
        domain,
        args.org_domain,
        report['report-id'],
    )
    msg['To'] = rua
    # XXX:fixme: make this configurable
    msg['From'] = 'SMTP TLS Report by %s <%s>' % (args.org_name, smtp_from)
    msg['TLS-Report-Domain'] = domain
    msg['TLS-Report-Submitter'] = args.org_domain

    body  = 'This is an aggregate TLS report from %s\n' % args.org_domain
    body += '\n'
    body += 'For your convenience:\n'
    body += json.dumps(report, indent=4)
    mime_body = email.mime.text.MIMEText(body)
    msg.attach(mime_body)

    report_json = json.dumps(report)
    report_gz = gzip.compress(report_json.encode())
    filename = '%s!%s!%s!%s!001.json.gz' % (
        args.org_domain,
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
            warn('Failed to send mail to: %s' % failed_recipients)
    
def mail_report(rua, report):
    if args.no_mails:
        return
    # strip 'mailto:' prefix
    rua_email = rua[7:]
    send_mail(rua_email, report)
    return

# # HTTP debugging
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
    domain = report['policies'][0]['policy']['policy-domain']
    print('POSTing report to %s (domain:%s)' % (rua, domain))
    headers =  {'Content-Type': 'application/tlsrpt+gzip'}
    report_json = json.dumps(report)
    report_gz = gzip.compress(report_json.encode())
    if args.dry_run:
        print(dsep)
        print('POST %s headers=%s\n%s\n' % (rua, headers, json.dumps(report, indent=4)))
        print(dsep)
        return
    try:
        response = requests.post(rua, data=report_gz, headers=headers)
    except requests.exceptions.ConnectionError as e:
        warn('POST to "%s" failed with ConnectionError: %s' % (rua, e))
        return
    if not response.ok:
        warn('POST to "%s" failed with %s %s: %s' % (rua, response.status_code, response.reason, response.text))
        return
    send_mail('POST@%s' % re.sub(r'[/?&]', '.', rua[8:]), report, fake=True)
    return

def send_report(tlsrpt):
    if tlsrpt['policy_type'] == 'none':
        return
    rua = tlsrpt['report']
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
    rua_methods[method](rua, gen_report(tlsrpt))



# ARGUMENTS
default_lmdb = '/var/spool/exim4/lmdb2/'
default_org_domain = 'invalid'
default_contact = 'smtp-tls-reports@invalid'
yesterday = datetime.date.today() - datetime.timedelta(days=1)
default_only_domains = []
default_ignore_domains = []
parser = argparse.ArgumentParser(description='MTA-STS report generator')
parser.add_argument('--lmdb',       type=str, help="path to mta-lmdb.pl's lmdb database", default=default_lmdb)
parser.add_argument('--org-domain', type=str, help='organization domain in reports',      default=default_org_domain)
parser.add_argument('--org-name',   type=str, help='organization name in reports',        default=default_org_domain)
parser.add_argument('--contact',    type=str, help='contact info in reports',             default=default_contact)
parser.add_argument('--date',       type=str, help='ISO date of report (def: yesterday)', default=str(yesterday))
parser.add_argument('--bcc',        type=str, help='BCC for send mails, comma seperated')
parser.add_argument('--only-domains',   type=str, help='only handle these domains, comma seperated', default=','.join(default_only_domains))
parser.add_argument('--ignore-domains', type=str, help='ignore these domains, comma seperated',      default=','.join(default_ignore_domains))
parser.add_argument('--dry-run',    action='store_true', help='do not MAIL or POST reports')
parser.add_argument('--no-mails',   action='store_true', help='do not MAIL reports')
parser.add_argument('--no-posts',   action='store_true', help='do not POST reports')
parser.add_argument('logfiles',   type=str, help='exim log files', nargs='+')
args = parser.parse_args()
if args.org_name == default_org_domain and args.org_domain != args.org_name:
    args.org_name = args.org_domain
only_domains   = args.only_domains.split(',')   if len(args.only_domains)   else []
ignore_domains = args.ignore_domains.split(',') if len(args.ignore_domains) else []
startdate = datetime.date.fromisoformat(args.date)
starttime = datetime.datetime.fromisoformat(startdate.isoformat())
endtime   = starttime + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
dsep = '='*200


# open LMDB database
env = lmdb.open(args.lmdb, max_dbs=10)
db = env.open_db()
# iterate over all entries
with env.begin() as txn:
    # the very first entry is the name of the db and the value is not decodable, so we skip it
    for key, value in list(txn.cursor(db=db))[1:]:
        k, v = key.decode(), value.decode()
        domain, attr = k.split(':', maxsplit=1)
        # store the domain as part of the 'tlsrpt' struct
        tlsrpt_data[domain]['domain'] = domain
        # store all values in the corresponding attr
        tlsrpt_data[domain][attr] = v.split(':') if attr == 'mx' else v


# generate a regex from all domains
exim_delivery_re = r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .+ (?P<delivered>[=-][>=]) (?P<recipient>\S+@(?P<domain>\S+))( (.* )?P=<(?P<sender>\S+)>)? .+ H=(?P<mxhost>\S+) .+$'
# read the exim logfile
def match_mx(host, mx_list):
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
            # convert (local) time from log to UTC
            localdt = datetime.datetime.fromisoformat( delivery_match.group('ts') )
            utcdt = localtz2utc(localdt)
            # skip if log entry is outside start2end time frame
            if utcdt < starttime or endtime < utcdt:
                continue
            line = line.strip()
            # check if successful delivery or defer
            delivered = delivery_match.group('delivered').endswith('>')
            # get the matched recipient address
            recipient = delivery_match.group('recipient')
            # get the matched recipient domain
            domain = delivery_match.group('domain')
            # get the matched sender address
            sender = delivery_match.group('sender')
            # get the used MX host
            mxhost = delivery_match.group('mxhost')
            if domain in ignore_domains:
                #warn('Ignoring domain "%s", in ignore_domains=%s' % (domain, ignore_domains))
                continue
            if len(only_domains) > 0 and domain not in only_domains:
                #warn('Ignoring domain "%s", not in only_domains=%s' % (domain, only_domains))
                continue
            if domain not in tlsrpt_data:
                tlsrpt_data[domain] = non_mtasts_domain(domain)
            rua = tlsrpt_data[domain]['report']
            if rua is None:
                #warn('Ignoring domain %s without rua set: %s' % (domain, line))
                continue
            tlsrpt_data[domain]['logs'].append(dict(
                line = line,
                delivered = delivered,
                recipient = recipient,
                sender = sender,
                mxhost = mxhost,
            ))
            # check if mx hostnames do no match this delivery line
            if tlsrpt_data[domain]['policy_type'] in ['sts', 'tlsa'] and not match_mx(mxhost, tlsrpt_data[domain]['mx']):
                warn('Warning: Host "%s" must not be used to deliver to domain "%s" according to policy:\n%s' % (mxhost, domain, tlsrpt_data[domain]['policy_type']))


# iterate over all domains
for domain, tlsrpt in tlsrpt_data.items():
    if len(tlsrpt['logs']) == 0:
        continue
    if tlsrpt['report'] is None:
        continue
    for logentry in tlsrpt['logs']:
        if logentry['sender'] == args.contact:
            #warn('Ignoring sender: %s' % logentry['sender'])
            continue
        if len([
                t for t in tlsrpt_data.values()
                if t['report'] == 'mailto:'+logentry['recipient']
        ]):
            warn('Ignoring recipient: %s' % logentry['recipient'])
            continue
        #warn('line: %s' % logentry['line'])
        # flag domain needs reporting
        tlsrpt_data[domain]['needsreport'] = True
        # store log line in 'deliveries' resp. 'errors'
        tlsrpt['deliveries' if logentry['delivered'] else 'errors'].append(logentry['line'])
    # skip domains, that do not need a report (no logs found)
    if not tlsrpt['needsreport']:
        continue
    # send report otherwise
    send_report(tlsrpt)
