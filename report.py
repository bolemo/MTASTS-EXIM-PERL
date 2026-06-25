#!/usr/bin/python3

'''
a report generator for TLSRPT report (RFC8460) using exim logs
'''

# I use 'return' and 'pass' to visualize end of functions or classes
# and to help emacs get indentation right
# pylint: disable=useless-return disable=unnecessary-pass
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
from dataclasses import dataclass, field, fields
import socket

import lmdb
import dns.resolver
import requests
try:
    import redis
    REDIS_AVAILABLE = True
except ModuleNotFoundError:
    REDIS_AVAILABLE = False
    pass

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

@dataclass
class TLSLogEntry:
    '''
    stores one parsed mail log line for TLS report generation
    '''
    line: str
    delivered: bool = True
    policy_error: bool = False
    recipient: str = None
    sender: str = None
    mxhost: str = None

@dataclass
class TLSRPT:
    # pylint: disable=too-many-instance-attributes
    '''
    store TLS report specific data for one domain
    '''
    # pylint: disable=invalid-name
    id: str = None
    domain: str = None
    policy: str = 'not stored'
    policy_type: str = 'sts'
    mode: str = None
    mx: list[str] = field(default_factory=list)
    # pylint: enable=invalid-name
    report: str = None
    expire: str = None

    def __post_init__(self):
        self._logs = []
        self._deliveries = 0
        self._errors = []
        self._failure_details = []
        return

    def __add__(self, other):
        if self.domain != other.domain:
            raise ValueError(
                f'Cannot add TLSRPT objects for different domains: {self.domain} vs. {other.domain}'
            )
        result = TLSRPT()
        # inherit dataclass fields from self
        for member in fields(self):
            setattr(result, member.name, getattr(self, member.name))
        # combine the list of logs
        result._logs = self._logs + other._logs
        # leave other protected members on their initial state
        return result

    def _parse_logs(self, ignore_from, ignore_to):
        for entry in self._logs:
            if entry.sender in ignore_from:
                debug(f'Ignoring sender: {entry.sender}')
                continue
            if entry.recipient in ignore_to:
                debug(f'Ignoring recipient: {entry.recipient}')
                continue
            #debug(f'line: {entry.line}')
            if entry.delivered:
                self._deliveries += 1
            if not entry.delivered or entry.policy_error:
                # adding add line to errors if delivery was not successful or policy error detected
                self._errors.append(entry.line)
        if self._errors:
            # now is a good time to analyse the error logs and store the result in 'failure_details'
            self._failure_details = parse_exim_errors(self._errors)
        return

    def add_logentry(self, entry):
        '''
        store logentry
        '''
        self._logs.append(entry)
        return

    def needs_report(self, ignore_from=[], ignore_to=[]):
        # pylint: disable=dangerous-default-value
        '''
        indicate if a report needs to be generates
        '''
        # without report destination, nothing to do
        if not self.report:
            return False
        # without log entries, nothing to do
        if not self._logs:
            return False
        self._parse_logs(ignore_from, ignore_to)
        if self._deliveries:
            return True
        if self._errors:
            return True
        return False

    def gen_report(self):
        # pylint: disable=missing-function-docstring
        policy = {
            "policy-type": self.policy_type,
            "policy-domain": self.domain,
        }
        if self.policy_type in ['sts', 'tlsa']:
            policy.update({
                "policy-string": self.policy.strip().split('\n'),
                "mx-host":       self.mx,
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
                        "total-successful-session-count": self._deliveries,
                        "total-failure-session-count": len(self._failure_details),
                    },
                },
            ],
        }
        if len(self._failure_details) > 0:
            report['policies'][0]['failure-details'] = self._failure_details
        return report

    def to_json(self, indent=None):
        '''
        convert required data to json representation
        '''
        jsondata = {
            member.name: getattr(self, member.name)
            for member in fields(self)
        }
        jsondata.update(dict(
            deliveries=self._deliveries,
            failure_details=self._failure_details,
        ))
        return json.dumps(jsondata, indent=indent)

    @classmethod
    def from_json(cls, jsondata):
        '''
        convert json representation TLSRPT obj
        '''
        data = json.loads(jsondata)
        obj = cls()
        for member in fields(obj):
            setattr(obj, member.name, data[member.name])
        obj._deliveries = data.get('deliveries', 0)
        obj._failure_details = data.get('failure_details', [])
        return obj

    pass


tlsrpt_data = defaultdict(TLSRPT)
error_domains = set()

def dns_resolve_rrset(qname, rdtype):
    '''
    resolve a given qname+rdtype and return a set of resource records or an empty set on error
    '''
    try:
        answer = dns.resolver.resolve(qname, rdtype, lifetime=20, search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
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
    rpt = TLSRPT(
        domain = domain,
        policy = 'no-policy-found',
        policy_type = 'no-policy-found',
    )
    domain_rua = get_tlsrpt_rua(domain)
    if domain_rua is None:
        # no TLSRPT record: none policy
        rpt.policy_type = 'none'
        return rpt
    rpt.report = domain_rua
    tlsa_mx = get_tlsa_mx(domain)
    if len(tlsa_mx) > 0:
        # TLSA records found, DANE in use
        rpt.policy_type = 'tlsa'
        rpt.policy = ';'.join(tlsa_mx.values())
        rpt.mx = list(tlsa_mx.keys())
    return rpt

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
    offset = dt - datetime.datetime.fromtimestamp(localts, datetime.UTC).replace(tzinfo=None)
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
    offset = dt - datetime.datetime.fromtimestamp(localts, datetime.UTC).replace(tzinfo=None)
    # return datetime object adjusted by computed offset
    return dt + offset

def exim_error2tlsrpt_error(error):
    # pylint: disable=missing-function-docstring
    ignored = [
        'SMTP timeout ',
        'SMTP error from remote mail server ',
        'Connection timed out',
        'Remote host closed connection in response to initial connection',
    ]
    for ign in ignored:
        if error.startswith(ign):
            debug(f'ignored: {error}')
            return None, None

    errors = {
        # pylint: disable=line-too-long
        # https://easydmarc.com/blog/de/simple-mail-transfer-protocol-smtp-tls-berichterstattung/
        'a TLS session is required, but the server did not offer TLS support': 'starttls-not-supported',
        # unfortunately exim always reports 'certificate invalid'
        # and does not report if the cert has a host mismatch, expiry or trust issue
        'TLS session: (certificate verification failed): certificate invalid': 'validation-failure',
        'TLS session: (certificate verification failed): Verification failed. The certificate differs.': 'validation-failure',
        'TLS session: (certificate verification failed)': 'validation-failure',
    }
    result_type = errors.get(error)
    if not result_type and ' must not be used to deliver to domain ' in error:
        result_type = 'validation-failure'
    if result_type:
        return result_type, error

    warn(f'Unknown error string "{error}"!')
    return 'validation-failure', 'unknown failure'

def parse_exim_errors(lines):
    # pylint: disable=missing-function-docstring disable=too-many-locals
    errors = defaultdict(int)
    # pylint: disable=line-too-long
    # 2023-03-10 17:58:55 1paeYC-001MTh-0L == measurement@mail-mtasts-rn-plain.measurement.email-security-scans.org R=dnslookup T=remote_smtp_mtasts_enforce defer (-38) H=plaintext.measurement.email-security-scans.org [2a06:d1c0:dead:3::83] I=[2a06:d1c0:dead:2::182] DT=0s: a TLS session is required, but the server did not offer TLS support
    # 2026-02-02 04:49:32 1vmkcr-00000003gVc-3F74 == dmarc-rpt@domeneshop.no R=dnslookup T=remote_smtp defer (110): Connection timed out H=mx.domeneshop.no [194.63.252.21] I=[139.19.205.225] DT=2m15s
    # 2026-02-16 03:20:47 1vroCe-0000000EHVq-3NEg => 2fincamt@tls.au.dmarcian.com P=<smtp-tls-reports@mpi-klsb.mpg.de> R=dnslookup T=remote_smtp S=2991 H=tls.au.dmarcian.com [34.116.117.45] I=[139.19.205.192] X=TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256 CV=yes DN="CN=au-app.au.dmarcian.com" C="250 2.0.0 Ok: queued as 3EB0D28D9E4" QT=1m35s DT=6s Policy-Error: Host "tls.au.dmarcian.com" must not be used to deliver to domain "tls.au.dmarcian.com" according to policy "sts"
    error_re = r'^.+ == (?P<email>\S+) (.+ H=(?P<mxhost>\S+) \[(?P<mxip>\S+)\] I=\[(?P<lip>\S+)\].*?: (?P<error>.+)|.+: (?P<error_alt>.+) H=(?P<mxhost_alt>\S+) \[(?P<mxip_alt>\S+)\] I=\[(?P<lip_alt>\S+)\] .+)$'
    policy_error_re = r'.+ [=-]> (?P<email>\S+) .+ H=(?P<mxhost>\S+) \[(?P<mxip>\S+)\] I=\[(?P<lip>\S+)\].* Policy-Error: (?P<error>.+)$'
    # pylint: enable=line-too-long
    for curline in lines:
        error_match = re.match(error_re, curline)
        if error_match:
            alt = '' if error_match.group('error') else '_alt'
            f_mxhost = error_match.group('mxhost'+alt)
            f_mxip   = error_match.group('mxip'+alt)
            f_lip    = error_match.group('lip'+alt)
            f_error  = error_match.group('error'+alt)
        policy_error_match = re.match(policy_error_re, curline)
        if not error_match and policy_error_match:
            f_mxhost = policy_error_match.group('mxhost')
            f_mxip   = policy_error_match.group('mxip')
            f_lip    = policy_error_match.group('lip')
            f_error  = policy_error_match.group('error')
        if not error_match and not policy_error_match:
            warn(f'Failed to match error line against "{error_re}":\n{curline}')
            continue
        result_type, reason = exim_error2tlsrpt_error(f_error)
        if result_type is None:
            continue
        error_key = (result_type, f_lip, f_mxip, f_mxhost, reason)
        errors[error_key] += 1
        continue
    result = []
    for error_key, count in errors.items():
        result_type, sender_ip, receiver, receiving_mx, reason = error_key
        res = {
            "result-type":           result_type,
            "sending-mta-ip":        sender_ip,
            "receiving-ip":          receiver,
            "receiving-mx-hostname": receiving_mx,
            "failed-session-count":  int(count),
        }
        if reason:
            res['failure-reason-code'] = reason
        result.append(res)
    return result

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
    _rua_emails = [val[7:] for val in rua_values]
    send_mail(_rua_emails, report)
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
        report_headers = dict(headers)
        report_data = report_gz
        if 'proton.me' in rua_address:
            debug(
                'Sending uncompressed data to proton.me '
                'until they make the endpoint RFC-compliant.'
            )
            report_headers['Content-Type'] = 'application/json'
            report_data = report_json
        if args.dry_run:
            print('\n'.join([
                DEBUG_SEP,
                f'POST {rua_address} headers={report_headers}\n{json.dumps(report, indent=4)}\n',
                DEBUG_SEP
            ]))
            continue
        send_mail([f"POST@{re.sub('[/?&]', '.', rua_address[8:])}"], report, fake=True)
        try:
            response = requests.post(
                rua_address,
                data=report_data,
                headers=report_headers,
                timeout=60
            )
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

def send_report(rpt):
    # pylint: disable=missing-function-docstring
    if rpt.policy_type == 'none':
        return
    rua_values = rpt.report
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
        rua_methods[method](rua_values, rpt.gen_report())
    return

def redis_connect(write=False):
    # pylint: disable=missing-function-docstring
    debug(f'redis_servers={redis_servers}')
    servers = list(redis_servers)
    debug(f'servers={servers}')
    if write:
        # write only to the first server
        servers = [ servers[0] ]
    else:
        # read from second to last and then first (RW) server
        servers.append(servers.pop(0))
    debug(f'servers={servers}')
    for server in servers:
        debug(f'redis.Redis(host={server},decode_responses=True)')
        conn = redis.Redis(host=server, decode_responses=True)
        if not conn:
            debug(f'redis.Redis(host={server},decode_responses=True) FAILED, continuing')
            continue
        debug(f'redis.Redis(host={server},decode_responses=True) CONNECTED')
        if args.redis_auth:
            conn.auth(args.redis_auth)
        debug(f'redis.Redis(host={server},decode_responses=True) AUTHENTICATED')
        return conn
    raise ConnectionError(
        f'Failed to connect to redis server {servers} ({"read/write" if write else "read-only"})'
    )

def redis_close(conn):
    # pylint: disable=missing-function-docstring
    if not conn:
        return
    debug('redis_close()')
    conn.close()
    return

def redis_store_report(rpt, conn):
    # pylint: disable=missing-function-docstring
    date = datetime.date.fromisoformat(args.date).isoformat()
    redis_key = f'{REDIS_KEY_PREFIX}:{rpt.domain}:{analysis_id}:{date}'
    if args.dry_run:
        print(f'conn.set({redis_key}, {rpt.to_json()}, ex={REDIS_LIFETIME})')
        return
    debug(f'redis.set({redis_key}, {rpt.to_json()}, ex={REDIS_LIFETIME})')
    conn.set(redis_key, rpt.to_json(), ex=REDIS_LIFETIME)
    return

def redis_load_reports():
    # pylint: disable=missing-function-docstring
    date = datetime.date.fromisoformat(args.date).isoformat()
    conn = redis_connect()
    keys = conn.keys(f'{REDIS_KEY_PREFIX}:*:*:{date}')
    key_suffix = '_processing' if not args.dry_run else ''
    reports = {
        redis_key+key_suffix: conn.get(redis_key)
        for redis_key in keys
        if not only_domains or redis_key.split(':')[1] in only_domains
    }
    redis_close(conn)
    if not args.dry_run:
        suffix_len = len(key_suffix)
        debug(f'key_suffix={key_suffix}, suffix_len={suffix_len}')
        conn = redis_connect(write=True)
        for redis_key in reports.keys():
            old_redis_key = redis_key[:len(redis_key)-suffix_len]
            debug(f'redis.rename({old_redis_key}, {redis_key})')
            conn.rename(old_redis_key, redis_key)
        redis_close(conn)
    return reports

def redis_remove_keys(keys):
    # pylint: disable=missing-function-docstring
    if not keys:
        return
    conn = redis_connect(write=True)
    if args.dry_run:
        print(f'conn.delete({keys})')
        return
    debug(f'redis.delete({keys})')
    conn.delete(*keys)
    redis_close(conn)

# ARGUMENTS
DEFAULT_LMDB = '/var/spool/exim4/lmdb2/'
DEFAULT_ORG_DOMAIN = 'invalid'
DEFAULT_CONTACT = 'smtp-tls-reports@invalid'
DEFAULT_ANALYSIS_ID = socket.gethostname()
yesterday = datetime.date.today() - datetime.timedelta(days=1)
default_only_domains = []
default_ignore_domains = []
default_ignore_recipients = []
default_ignore_senders = []
parser = argparse.ArgumentParser(description='MTA-STS report generator')
# pylint: disable=line-too-long
parser.add_argument('--lmdb',       type=str, help="path to mta-lmdb.pl's lmdb database", default=DEFAULT_LMDB)
parser.add_argument('--org-domain', type=str, help='organization domain in reports',      default=DEFAULT_ORG_DOMAIN)
parser.add_argument('--org-name',   type=str, help='organization name in reports',        default=DEFAULT_ORG_DOMAIN)
parser.add_argument('--contact',    type=str, help='contact info in reports',             default=DEFAULT_CONTACT)
parser.add_argument('--date',       type=str, help='ISO date of report (def: yesterday)', default=str(yesterday))
parser.add_argument('--bcc',        type=str, help='BCC for send mails, comma seperated')
parser.add_argument('--only-domains',   type=str, help='only handle these domains, comma seperated', default=','.join(default_only_domains))
parser.add_argument('--ignore-domains', type=str, help='ignore these domains, comma seperated',      default=','.join(default_ignore_domains))
parser.add_argument('--ignore-recipients', type=str, help='ignore rua recipients, comma seperated',      default=','.join(default_ignore_recipients))
parser.add_argument('--ignore-senders', type=str, help='ignore log entries from these senders, comma seperated',      default=','.join(default_ignore_senders))
parser.add_argument('--dry-run',    action='store_true', help='do not MAIL or POST reports')
parser.add_argument('--no-mails',   action='store_true', help='do not MAIL reports')
parser.add_argument('--no-posts',   action='store_true', help='do not POST reports')
parser.add_argument('--verbose',    action='store_true', help='be verbose')
parser.add_argument('logfiles',   type=str, help='exim log files', nargs='*' if REDIS_AVAILABLE else '+')
if REDIS_AVAILABLE:
    parser.add_argument('--analyse-only',  action='store_true', help='only analyse the logs and store the results in redis')
    parser.add_argument('--send-analysis', action='store_true', help='only send analysis results stored in redis (no logfiles required)')
    parser.add_argument('--redis-servers', type=str, help='use these redis servers, sepereated by "/". If multiple given, first is rw, others ro')
    parser.add_argument('--redis-auth',    type=str, help='password for redis servers')
    parser.add_argument('--analysis-id',   type=str, help=f'id for storing, default: hostname ({DEFAULT_ANALYSIS_ID})', default=DEFAULT_ANALYSIS_ID)
# pylint: enable=line-too-long
args = parser.parse_args()
redis_servers = []
if REDIS_AVAILABLE and args.redis_servers:
    redis_servers = args.redis_servers.split('/')
analyse_only  = args.analyse_only  if REDIS_AVAILABLE else False
send_analysis = args.send_analysis if REDIS_AVAILABLE else False
analysis_id   = args.analysis_id   if REDIS_AVAILABLE else None
if analyse_only and send_analysis:
    warn('You cannot specify both --analyse-only and --send-analysis')
    parser.print_help()
    sys.exit(1)
if not send_analysis and not args.logfiles:
    warn('Please specify some logfiles to analyse')
    parser.print_help()
    sys.exit(1)
if (analyse_only or send_analysis) and not redis_servers:
    warn('Options --analyse-only and --send-analysis require --redis-servers')
    parser.print_help()
    sys.exit(1)
if args.org_name == DEFAULT_ORG_DOMAIN and args.org_domain != args.org_name:
    args.org_name = args.org_domain
only_domains   = args.only_domains.split(',')   if len(args.only_domains)   else []
ignore_domains = args.ignore_domains.split(',') if len(args.ignore_domains) else []
ignore_recipients = args.ignore_recipients.split(',') if len(args.ignore_recipients) else []
ignore_senders = args.ignore_senders.split(',') if len(args.ignore_senders) else []
startdate = datetime.date.fromisoformat(args.date)
starttime = datetime.datetime.fromisoformat(startdate.isoformat())
endtime   = starttime + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
DEBUG_SEP = '='*200
REDIS_LIFETIME = datetime.timedelta(days=2)
REDIS_KEY_PREFIX = 'tlsrpt'

if send_analysis:
    stored_reports = redis_load_reports()
    tlsrpts = {}
    for stored_report in stored_reports.values():
        tlsrpt = TLSRPT.from_json(stored_report)
        old_tlsrpt = tlsrpts.get(tlsrpt.domain)
        tlsrpts[tlsrpt.domain] = old_tlsrpt + tlsrpt \
            if old_tlsrpt else \
               tlsrpt
    for tlsrpt in tlsrpts.values():
        send_report(tlsrpt)
    redis_remove_keys(stored_reports.keys())
    sys.exit(0)

# open LMDB database
env = lmdb.open(args.lmdb, max_dbs=10, readonly=True)
db = env.open_db()
# iterate over all entries
with env.begin() as txn:
    # the very first entry is the name of the db and the value is not decodable, so we skip it
    for key, value in list(txn.cursor(db=db))[1:]:
        k, v = key.decode(), value.decode()
        domain, attr = k.split(':', maxsplit=1)
        # store the domain as part of the 'tlsrpt' struct
        tlsrpt_data[domain].domain = domain
        # store all values in the corresponding attr
        setattr(tlsrpt_data[domain], attr, v.split(':') if attr == 'mx' else v)


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
    # errors='replace' to allow parsing bad UTF-8 encodings
    with file_open(logfile, mode='rt', encoding='utf-8', errors='replace') as f:
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
                debug(f'Ignoring domain "{domain}", in ignore_domains={ignore_domains}')
                continue
            if len(only_domains) > 0 and domain not in only_domains:
                debug(f'Ignoring domain "{domain}", not in only_domains={only_domains}')
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
            rua = tlsrpt_data[domain].report
            if rua is None:
                debug(f'Ignoring domain {domain} without rua set: {line}')
                continue
            if rua == '':
                debug(f'Ignoring domain {domain} with rua set to "": {line}')
                continue
            if rua.startswith('mailto:') and rua[7:] in ignore_recipients:
                debug(
                    f'Ignoring domain "{domain}", '
                    f'rua {rua} in ignore_recipients={ignore_recipients}'
                )
                continue
            # check if mx hostnames do no match this delivery line,
            # but only for successful deliveries
            policy_error = False # pylint: disable=invalid-name
            if tlsrpt_data[domain].policy_type in ['sts', 'tlsa'] and \
               not match_mx(mxhost, tlsrpt_data[domain].mx) and \
               delivered:
                debug(
                    f'Warning: Host "{mxhost}" must not be used to deliver to domain "{domain}" '
                    f' according to policy: {tlsrpt_data[domain].policy_type}'
                    f' mxhosts={tlsrpt_data[domain].mx}'
                    f' line: {line}'
                )
                line += (
                    f' Policy-Error: Host {mxhost} must not be used to deliver'
                    f' to domain {domain}'
                    f' according to policy {tlsrpt_data[domain].policy_type}'
                    f' see https://datatracker.ietf.org/doc/html/rfc8461#section-5'
                )
                # pylint: disable=invalid-name
                policy_error = True
            tlsrpt_data[domain].add_logentry(TLSLogEntry(
                line = line,
                delivered = delivered,
                policy_error = policy_error,
                recipient = recipient,
                sender = sender,
                mxhost = mxhost,
            ))


# extract all rua email addresses
rua_emails = [
    t.report[7:]
    for t in tlsrpt_data.values()
    if t.report and t.report.startswith('mailto:')
]

# connect to redis RW server, but only if we only want to analyse
redis_conn = redis_connect(write=True) if analyse_only else None

# iterate over all domains
for domain, tlsrpt in tlsrpt_data.items():
    if not tlsrpt.needs_report(
            ignore_from=[ args.contact ] + ignore_senders,
            ignore_to=rua_emails,
    ):
        continue
    if analyse_only:
        redis_store_report(tlsrpt, redis_conn)
        continue
    # send report otherwise
    send_report(tlsrpt)

# disconnect from redis, if connected
redis_close(redis_conn)
