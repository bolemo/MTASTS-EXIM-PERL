#!/usr/bin/python3

'''
a report generator for TLSRPT report (RFC8460) using exim logs
'''

# I use 'return' to visualize end of functions and to help emacs get indentation right
# pylint: disable=useless-return
# using dict() instead of {} avoids much quoting
# pylint: disable=use-dict-literal

import sys
import argparse
import io
import gzip
import re
import datetime
import json
import email.mime.multipart
import email.mime.text
import email.mime.application
import smtplib
from collections import defaultdict

import lmdb
import dns.resolver
import requests

def warn(msg):
    # pylint: disable=missing-function-docstring
    print(msg, file=sys.stderr)
    return

def debug(msg):
    # pylint: disable=missing-function-docstring
    if not args.verbose:
        return
    print(msg)
    return

# initialize the fields of out tlsrpt data
def tlsrpt_struct():
    # pylint: disable=missing-function-docstring
    return dict(
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
        failure_details=[],
    )
tlsrpt_data = defaultdict(tlsrpt_struct)
error_domains = set()

def dns_resolve_rrset(qname, rdtype):
    '''
    resolve a given qname+rdtype and return a set of resource records or an empty set on error
    '''
    try:
        answer = dns.resolver.resolve(qname, rdtype, lifetime=20, search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return set()
    # dns.rdtypes.ANY.TXT.TXT's to_text is somehow broken, we parse TXT records better on our own
    def rr2text(rr): # pylint: disable=invalid-name
        if rdtype != 'TXT':
            return rr.to_text()
        return '"'+''.join([s.decode() for s in rr.strings])+'"'
    return { rr2text(rr) for rr in answer }

def get_tlsrpt_rua(domain): # pylint: disable=redefined-outer-name
    '''
    returns rua value of domain's DNS TLSRPT record or None if no such record found
    '''
    for record in dns_resolve_rrset(f'_smtp._tls.{domain}', 'TXT'):
        # record='"v=TLSRPTv1; rua=email@domain.tld"'
        if not record.startswith('"v=TLSRPTv1;'):
            continue
        tlsrpt_value = record[12:-1].strip()
        if tlsrpt_value.endswith(';'):
            # RFC8460 allows an optional ';' at the end
            tlsrpt_value = tlsrpt_value[:-1].strip()
        if re.match('.*[ ;]', tlsrpt_value):
            warn(f'Illegal TLSRPT record of domain {domain}: {record}')
            continue
        # "rua=..."
        return tlsrpt_value[4:]
    return None

def get_tlsa_mx(domain): # pylint: disable=redefined-outer-name
    '''
    returns a dict of mx: tlsa_rrset of domain for all MX with valid TLSA records
    '''
    tlsa_mx = {}
    for mx_record in dns_resolve_rrset(domain, 'MX'):
        _, mx_target = mx_record.split()
        tlsa = [
            f'_25._tcp.{mx_target} IN TLSA {tlsa_record}'
            for tlsa_record in dns_resolve_rrset(f'_25._tcp.{mx_target}', 'TLSA')
        ]
        if not tlsa:
            continue
        # remove trailing '.' from mx_target to allow matching in mail logs
        while mx_target.endswith('.'):
            mx_target = mx_target[:-1]
        tlsa_mx[mx_target] = ';'.join(tlsa)
    return tlsa_mx

def non_mtasts_domain(domain): # pylint: disable=redefined-outer-name
    '''
    generate tlsrpt struct for a non-MTA-STS domain
    '''
    data = tlsrpt_struct()
    data.update(dict(
        domain = domain,
        policy = 'no-policy-found',
        policy_type = 'no-policy-found',
    ))
    domain_rua = get_tlsrpt_rua(domain)
    if domain_rua is None:
        # no TLSRPT record: none policy
        data['policy_type'] = 'none'
        return data
    data['report'] = domain_rua
    tlsa_mx = get_tlsa_mx(domain)
    if len(tlsa_mx) > 0:
        # TLSA records found, DANE in use
        data.update(dict(
            policy_type = 'tlsa',
            policy = ';'.join(tlsa_mx.values()),
            mx = list(tlsa_mx.keys()),
        ))
    return data

def localtz2utc(dt): # pylint: disable=invalid-name
    '''
    convert a datetime object from local time to UTC
    inspired by
    https://stackoverflow.com/questions/4770297/convert-utc-datetime-string-to-local-datetime
    '''
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
def utc2localtz(dt): # pylint: disable=invalid-name
    '''
    convert given (utc) datetime object to a LOCAL timestamp
    '''
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
    # pylint: disable=missing-function-docstring
    errors = {
        # pylint: disable=line-too-long
        # https://easydmarc.com/blog/de/simple-mail-transfer-protocol-smtp-tls-berichterstattung/
        'a TLS session is required, but the server did not offer TLS support': 'starttls-not-supported',
        # unfortunately exim always reports 'certificate invalid'
        # and does not report if the cert has a host mismatch, expiry or trust issue
        'TLS session: (certificate verification failed): certificate invalid': 'validation-failure',
        'TLS session: (certificate verification failed): Verification failed. The certificate differs.': 'validation-failure',
    }
    if error in errors:
        return errors[error]
    ignored = [
        'SMTP timeout ',
        'SMTP error from remote mail server ',
        'Connection timed out',
    ]
    for ign in ignored:
        if error.startswith(ign):
            return None
    warn(f'Unknown error string "{error}"!')
    return 'validation-failure'

def parse_exim_errors(lines):
    # pylint: disable=missing-function-docstring
    errors = defaultdict(int)
    # pylint: disable=line-too-long
    # 2023-03-10 17:58:55 1paeYC-001MTh-0L == measurement@mail-mtasts-rn-plain.measurement.email-security-scans.org R=dnslookup T=remote_smtp_mtasts_enforce defer (-38) H=plaintext.measurement.email-security-scans.org [2a06:d1c0:dead:3::83] I=[2a06:d1c0:dead:2::182] DT=0s: a TLS session is required, but the server did not offer TLS support
    # 2026-02-02 04:49:32 1vmkcr-00000003gVc-3F74 == dmarc-rpt@domeneshop.no R=dnslookup T=remote_smtp defer (110): Connection timed out H=mx.domeneshop.no [194.63.252.21] I=[139.19.205.225] DT=2m15s
    error_re = r'^.+ == (?P<email>\S+) (.+ H=(?P<mxhost>\S+) \[(?P<mxip>\S+)\] I=\[(?P<lip>\S+)\].*?: (?P<error>.+)|.+: (?P<error_alt>.+) H=(?P<mxhost_alt>\S+) \[(?P<mxip_alt>\S+)\] I=\[(?P<lip_alt>\S+)\] .+)$'
    # pylint: enable=line-too-long
    for curline in lines:
        error_match = re.match(error_re, curline)
        if not error_match:
            warn(f'Failed to match error line against "{error_re}":\n{curline}')
            continue
        alt = '' if error_match.group('error') else '_alt'
        #f_email  = error_match.group('email'+alt)
        f_mxhost = error_match.group('mxhost'+alt)
        f_mxip   = error_match.group('mxip'+alt)
        f_lip    = error_match.group('lip'+alt)
        f_error  = error_match.group('error'+alt)
        result_type = exim_error2tlsrpt_error(f_error)
        if result_type is None:
            continue
        error_key = (result_type, f_lip, f_mxip, f_mxhost)
        errors[error_key] += 1
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

def gen_report(data):
    # pylint: disable=missing-function-docstring
    policy = {
        "policy-type": data['policy_type'],
        "policy-domain": data['domain'],
    }
    if data['policy_type'] in ['sts', 'tlsa']:
        policy.update({
            "policy-string": data['policy'].strip().split('\n'),
            "mx-host":       data['mx'],
        })
    report = {
        "organization-name": args.org_name,
        "date-range": {
            "start-datetime": starttime.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "end-datetime":   endtime.strftime('%Y-%m-%dT%H:%M:%SZ'),
        },
        "contact-info": args.contact,
        # pylint: disable=consider-using-f-string # printf format better readable
        "report-id": "%s@%s" % (
            localtz2utc( datetime.datetime.now() ).strftime('%Y-%m-%dT%H:%M:%SZ'),
            args.org_domain
        ),
        "policies": [
            {
                "policy": policy,
                "summary": {
                    "total-successful-session-count": len(data['deliveries']),
                    "total-failure-session-count": len(data['failure_details']),
                },
            },
        ],
    }
    if len(data['failure_details']) > 0:
        report['policies'][0]['failure-details'] = data['failure_details']
    return report

def send_mail(rua_addresses, report, fake=False):
    # pylint: disable=missing-function-docstring
    # pylint: disable=too-many-locals
    cur_domain = report['policies'][0]['policy']['policy-domain']
    smtp_from = args.contact
    debug(f'Mailing report to {rua_addresses} (domain:{cur_domain})')
    smtp_to = rua_addresses if not fake else []
    if args.bcc:
        smtp_to += args.bcc.split(',')

    msg = email.mime.multipart.MIMEMultipart(_subtype='report')
    msg.set_param('report-type', 'tlsrpt')
    msg['Subject'] = (
        f"Report Domain: {cur_domain} "
        f"Submitter: {args.org_domain} "
        f"Report-ID: <{report['report-id']}>"
    )
    msg['To'] = ', '.join(rua_addresses)
    # XXX:fixme: make this configurable # pylint: disable=fixme
    msg['From'] = f'SMTP TLS Report by {args.org_name} <{smtp_from}>'
    msg['TLS-Report-Domain'] = cur_domain
    msg['TLS-Report-Submitter'] = args.org_domain

    body  = f'This is an aggregate TLS report from {args.org_domain}\n'
    body += '\n'
    body += 'For your convenience:\n'
    body += json.dumps(report, indent=4)
    # from https://stackoverflow.com/questions/14939018/encode-mimetext-as-quoted-printables
    # Construct a new charset which uses Quoted Printables (base64 is default)
    charset = email.charset.Charset('utf-8')
    charset.body_encoding = email.charset.QP
    # Now set the content using the new charset
    mime_body = email.mime.text.MIMEText(body, _charset=charset)
    msg.attach(mime_body)

    report_json = json.dumps(report)
    report_gz = gzip.compress(report_json.encode())
    filename = (
        f'{args.org_domain}!{cur_domain}!{int(starttime.timestamp())}!'
        f'{int(endtime.timestamp())}!001.json.gz'
    )
    mime_report = email.mime.application.MIMEApplication(report_gz, _subtype='tlsrpt+gzip')
    mime_report.add_header('content-disposition', 'attachment', filename=filename)
    msg.attach(mime_report)

    smtp_body = msg.as_string()
    if args.dry_run:
        print('\n'.join([
            DEBUG_SEP,
            smtp_body,
            DEBUG_SEP
        ]))
        return
    with smtplib.SMTP(host='localhost') as smtp:
        failed_recipients = smtp.sendmail(smtp_from, smtp_to, msg.as_string())
        if len(failed_recipients) > 0:
            warn(f'Failed to send mail to: {failed_recipients}')

def mail_report(rua_values, report):
    # pylint: disable=missing-function-docstring
    if args.no_mails:
        return
    # strip 'mailto:' prefix
    rua_emails = [val[7:] for val in rua_values]
    send_mail(rua_emails, report)
    return

# HTTP debugging
#import logging
## These two lines enable debugging at httplib level (requests->urllib3->http.client)
## You will see the REQUEST, including HEADERS and DATA, and RESPONSE
## with HEADERS but without DATA. The only thing missing will be the
## response.body which is not logged.
#import http.client as http_client
#http_client.HTTPConnection.debuglevel = 1
## You must initialize logging, otherwise you'll not see debug output.
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)

def post_report(rua_addresses, report):
    # pylint: disable=missing-function-docstring
    if args.no_posts:
        return
    cur_domain = report['policies'][0]['policy']['policy-domain']
    debug(f'POSTing report to {rua_addresses} (domain:{cur_domain})')
    headers =  {'Content-Type': 'application/tlsrpt+gzip'}
    report_json = json.dumps(report)
    report_gz = gzip.compress(report_json.encode())
    for rua_address in rua_addresses:
        if args.dry_run:
            print('\n'.join([
                DEBUG_SEP,
                f'POST {rua_address} headers={headers}\n{json.dumps(report, indent=4)}\n',
                DEBUG_SEP
            ]))
            continue
        send_mail([f"POST@{re.sub('[/?&]', '.', rua_address[8:])}"], report, fake=True)
        try:
            response = requests.post(rua_address, data=report_gz, headers=headers, timeout=60)
        except requests.exceptions.ConnectionError as connerr:
            warn(f'POST to "{rua_address}" failed with ConnectionError: {connerr}')
            continue
        except requests.exceptions.Timeout as timeouterr:
            warn(f'POST to "{rua_address}" failed with Timeout: {timeouterr}')
            continue
        if not response.ok:
            warn(
                f'POST to "{rua_address}" failed with {response.status_code} '
                f'{response.reason}: {response.text}'
            )
    return

def send_report(data):
    # pylint: disable=missing-function-docstring
    if data['policy_type'] == 'none':
        return
    rua_values = data['report']
    rua_methods = dict(
        mailto=mail_report,
        https=post_report,
    )
    tasks = defaultdict(list)
    for rua_value in rua_values.split(','):
        rua_value = rua_value.strip()
        try:
            method, _ = rua_value.split(':', maxsplit=1)
        except ValueError:
            # workaround for buggy db data before substr(,7) fix
            if rua_value.startswith('/'):
                method = 'https'
                rua_value = 'https:/'+rua_value
            else:
                method = 'mailto'
                rua_value = 'mailto:'+rua_value
        if method not in rua_methods:
            warn(f'Unsupported rua method "{method}" in rua "{rua_value}"!')
            continue
        tasks[method].append(rua_value)
    for method, rua_values in tasks.items():
        rua_methods[method](rua_values, gen_report(data))
    return

def print_tlsrpt(rpt):
    cp = {}
    for key, val in rpt.items():
        if key in ['logs', 'deliveries', 'errors', ]:
            val = len(val)
        cp[key] = val
    print(json.dumps(cp, indent=4))


# ARGUMENTS
DEFAULT_LMDB = '/var/spool/exim4/lmdb2/'
DEFAULT_ORG_DOMAIN = 'invalid'
DEFAULT_CONTACT = 'smtp-tls-reports@invalid'
yesterday = datetime.date.today() - datetime.timedelta(days=1)
default_only_domains = []
default_ignore_domains = []
default_ignore_senders = []
parser = argparse.ArgumentParser(description='MTA-STS report generator')
parser.add_argument('--lmdb',       type=str, help="path to mta-lmdb.pl's lmdb database", default=DEFAULT_LMDB)                                                 # pylint: disable=line-too-long
parser.add_argument('--org-domain', type=str, help='organization domain in reports',      default=DEFAULT_ORG_DOMAIN)                                           # pylint: disable=line-too-long
parser.add_argument('--org-name',   type=str, help='organization name in reports',        default=DEFAULT_ORG_DOMAIN)                                           # pylint: disable=line-too-long
parser.add_argument('--contact',    type=str, help='contact info in reports',             default=DEFAULT_CONTACT)                                              # pylint: disable=line-too-long
parser.add_argument('--date',       type=str, help='ISO date of report (def: yesterday)', default=str(yesterday))                                               # pylint: disable=line-too-long
parser.add_argument('--bcc',        type=str, help='BCC for send mails, comma seperated')                                                                       # pylint: disable=line-too-long
parser.add_argument('--only-domains',   type=str, help='only handle these domains, comma seperated', default=','.join(default_only_domains))                    # pylint: disable=line-too-long
parser.add_argument('--ignore-domains', type=str, help='ignore these domains, comma seperated',      default=','.join(default_ignore_domains))                  # pylint: disable=line-too-long
parser.add_argument('--ignore-senders', type=str, help='ignore log entries from these senders, comma seperated',      default=','.join(default_ignore_senders)) # pylint: disable=line-too-long
parser.add_argument('--dry-run',    action='store_true', help='do not MAIL or POST reports')
parser.add_argument('--no-mails',   action='store_true', help='do not MAIL reports')
parser.add_argument('--no-posts',   action='store_true', help='do not POST reports')
parser.add_argument('--verbose',    action='store_true', help='be verbose')
parser.add_argument('logfiles',   type=str, help='exim log files', nargs='+')
args = parser.parse_args()
if args.org_name == DEFAULT_ORG_DOMAIN and args.org_domain != args.org_name:
    args.org_name = args.org_domain
only_domains   = args.only_domains.split(',')   if len(args.only_domains)   else []
ignore_domains = args.ignore_domains.split(',') if len(args.ignore_domains) else []
ignore_senders = args.ignore_senders.split(',') if len(args.ignore_senders) else []
startdate = datetime.date.fromisoformat(args.date)
starttime = datetime.datetime.fromisoformat(startdate.isoformat())
endtime   = starttime + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
DEBUG_SEP = '='*200


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
exim_delivery_re = r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .+ (?P<delivered>[=-][>=]) (?P<recipient>\S+@(?P<domain>\S+))( (.* )?P=<(?P<sender>\S+)>)? .+ H=(?P<mxhost>\S+) .+$' # pylint: disable=line-too-long,invalid-name
# read the exim logfile
def match_mx(host, mx_list):
    # pylint: disable=missing-function-docstring
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
            if domain in error_domains:
                continue
            if domain not in tlsrpt_data:
                try:
                    tlsrpt_data[domain] = non_mtasts_domain(domain)
                except Exception as ex: # pylint: disable=broad-except
                    warn(
                        f'Error getting report config for non-mtasts domain {domain}, '
                        f'will ignore domain: {ex}'
                    )
                    error_domains.add(domain)
                    continue
            rua = tlsrpt_data[domain]['report']
            if rua is None:
                #warn('Ignoring domain %s without rua set: %s' % (domain, line))
                continue
            if rua == '':
                warn(f'Ignoring domain {domain} without rua set to "": {line}')
                continue
            tlsrpt_data[domain]['logs'].append(dict(
                line = line,
                delivered = delivered,
                recipient = recipient,
                sender = sender,
                mxhost = mxhost,
            ))
            # check if mx hostnames do no match this delivery line
            if tlsrpt_data[domain]['policy_type'] in ['sts', 'tlsa'] and \
               not match_mx(mxhost, tlsrpt_data[domain]['mx']):
                warn(
                    f'Warning: Host "{mxhost}" must not be used to deliver to domain "{domain}" '
                    f'according to policy:\n{tlsrpt_data[domain]["policy_type"]}'
                )


# iterate over all domains
for domain, tlsrpt in tlsrpt_data.items():
    if len(tlsrpt['logs']) == 0:
        continue
    if not tlsrpt['report']:
        continue
    for logentry in tlsrpt['logs']:
        if logentry['sender'] in [ args.contact ] + ignore_senders:
            #warn('Ignoring sender: %s' % logentry['sender'])
            continue
        if [
                t for t in tlsrpt_data.values()
                if t['report'] == 'mailto:'+logentry['recipient']
        ]:
            #warn('Ignoring recipient: %s' % logentry['recipient'])
            continue
        #warn('line: %s' % logentry['line'])
        # flag domain needs reporting
        tlsrpt['needsreport'] = True
        # store log line in 'deliveries' resp. 'errors'
        tlsrpt['deliveries' if logentry['delivered'] else 'errors'].append(logentry['line'])
    # skip domains, that do not need a report (no logs found)
    if not tlsrpt['needsreport']:
        continue
    # now is a good time to analyse the error logs and store the result in 'failure_details'
    tlsrpt['failure_details'] = parse_exim_errors(tlsrpt['errors'])
    # send report otherwise
    send_report(tlsrpt)
