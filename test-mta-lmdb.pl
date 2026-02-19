#!/usr/bin/perl

use strict;

#our $MTASTS_DEBUG = 1;
our $MTASTS_LMDB_PATH = '/tmp/lmdb';

do "./mta-lmdb.pl";

my @domains = qw(errror.org microsoft.com gmx.net gmail.com spiegel.de saarpfalz-kreis.de pandi.id financialanalystmail.com);

for my $domain (@domains) {
    print('RESULT OF mtasts_policy('.$domain.'): '.mtasts_policy($domain)."\n");
}
print("\n");

for my $domain_mx (qw(saarpfalz-kreis.de:mforward.dtag.de microsoft.com:mx.mail.protection.outlook.com pandi.id:mx.pandi.id financialanalystmail.com:financialanalystmail.com)) {
    my ($domain, $mx) = split(':', $domain_mx);
    print('RESULT OF mtasts_valid_mx('.$domain.', '.$mx.'): '.mtasts_valid_mx($domain, $mx)."\n");
    print('RESULT OF mtasts_valid_mx('.$domain.', mx.wrong.com): '.mtasts_valid_mx($domain, 'mx.wrong.com')."\n");
}
print("\n");

for my $domain (@domains) {
    print('RESULT OF mtasts_mx_hostlist('.$domain.'): '.mtasts_mx_hostlist($domain)."\n");
}
print('RESULT OF mtasts_mx_hostlist(unknown.domain): '.mtasts_mx_hostlist('unknown.domain')."\n");
print("\n");
