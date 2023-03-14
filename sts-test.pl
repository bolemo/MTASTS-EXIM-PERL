#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;

use Mail::STS;

my $domainname = $ARGV[0];
print("Domain: $domainname\n");

my $sts = Mail::STS->new;
my $domain = $sts->domain($domainname);
#print("\nMail::STS:Domain: $domain\n");
#print("\nMail::STS:Domain: ".Dumper($domain));

eval { $domain->record_type; } or
    die("Domain $domainname does not resolve\n");

my $tlsa = $domain->tlsa;
print("\nNet::DNS::RR::TLSA: ".Dumper($tlsa));

my $stsrecord = $domain->sts;
print("\nMail::STS::STSRecord: ".Dumper($stsrecord));
defined($stsrecord) or exit(0);

my $tlsrpt = $domain->tlsrpt;
print("\nMail::STS::TLSRPTRecord: ".Dumper($tlsrpt));
defined($tlsrpt) or exit(0);

my $policy = $domain->policy;
print("\nMail::STS::Policy: ".Dumper($policy));
defined($policy) or exit(0);
