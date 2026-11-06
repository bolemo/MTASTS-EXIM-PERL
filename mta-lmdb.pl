#!/usr/bin/perl

# (C) 2026 Patrick Cernko
# This is a reimplementation of mta-lmdb.pl from https://github.com/Bobberty/MTASTS-EXIM-PERL
# after forking and fixing it in 2023.

use strict;
use DateTime;
use Mail::STS;


# settings
our $MTASTS_DEBUG;     # set to 1 to enable debugging output
our $MTASTS_LMDB_PATH; # set to path where to store LMDB database, e.g. '<path-to-exim-spooldir>/lmdb2'
if (!defined($MTASTS_LMDB_PATH)) {
    $MTASTS_LMDB_PATH = '/var/spool/exim4/lmdb2';
}

# internal functions, declared here, defined below
sub _mtasts_debug($);
sub _mtasts_warning($);
sub _mtasts_sts_query($);
sub _mtasts_sts_load_policy($);
sub _mtasts_db_query($$);
sub _mtasts_db_save($$$$);


# main API functions

# returns the policy for exim to use for a given domain as string:
# - fail
# - dane
# - none
# - testing
# - enforce
# Input: the DNS domain to test MTA-STS for
sub mtasts_policy(@) {
    my ($domain, $submitter) = @_;

    _mtasts_debug('mtasts_policy('.$domain.', submitter-header:'.$submitter.')');

    # if submitter header value given, return policy none, see https://datatracker.ietf.org/doc/html/rfc8460#section-5.3.1
    if (defined($submitter) && ($submitter ne '')) {
        _mtasts_debug('mtasts_policy('.$domain.'): returning "none": Header TLS-Report-Submitter:'.$submitter.' requires that MTA-STS or DANE TLSA failures MUST NOT be honored.');
        return 'none';
    }

    # ensure domain is only lowercase
    $domain = lc($domain);

    # query STS for $domain
    my $STS = _mtasts_sts_query($domain);
    if ($STS->{dane}) {
        _mtasts_debug('mtasts_policy('.$domain.'): returning "dane": DANE is primary');
        return 'dane';
    }

    # get the current time for later computations
    my $now = DateTime->now()->epoch;

    # now open the database ...
    my $DB = _mtasts_db_query($domain, $now);
    if (! defined($DB)) {
        _mtasts_debug('mtasts_policy('.$domain.'): returning "fail": could not init DB');
        return 'fail';
    }

    # If there is a Policy in the DB and the MTA-STS version in the DNS is valid, check if the version numbers are the same.
    if ($DB->{valid} && defined($STS->{id}) && ($DB->{id} eq $STS->{id})) {
        # Policy in the DB is good and it hasn't expired.
        # Current policy found in the DB. Send the current mode.
        _mtasts_debug('mtasts_policy('.$domain.'): returning "'.$DB->{mode}.'" from DB');
        return $DB->{mode};
    }

    # If not, check if there is a STS id
    if (! defined($STS->{id})) {
        # No Policy in the DB and there is no MTA-STS record in the DNS.
        _mtasts_debug('mtasts_policy('.$domain.'): returning "none": No Policy in the DB and there is no MTA-STS record in the DNS');
        return 'none';
    }

    # No Policy in the DB or the policy in the DB is bad, but the MTA-STS version in the DNS is valid.
    # load the policy
    $STS = _mtasts_sts_load_policy($STS);
    # check if loading failed
    if (defined($STS->{policy_fail})) {
        if ($STS->{policy_fail} eq 'none') {
            _mtasts_debug('mtasts_policy('.$domain.'): returning "none": good MTA-STS DNS entry but no policy available from cache or http');
        } elsif ($STS->{policy_fail} eq 'fail') {
            _mtasts_debug('mtasts_policy('.$domain.'): returning "fail": badly formatted policy');
        } else {
            _mtasts_debug('mtasts_policy('.$domain.'): returning "fail": unknown result from _mtasts_sts_load_policy(): policy_fail='.$STS->{policy_fail});
            return 'fail';
        }
        return $STS->{policy_fail};
    };

    # and save in DB
    _mtasts_db_save($DB, $domain, $STS, $now);

    # Loaded the DB with a proper policy.  Send the current mode and have a nice day.
    _mtasts_debug('mtasts_policy('.$domain.'): returning "'.$STS->{mode}.'" (after updating DB)');
    return $STS->{mode};
}

# returns an empty string if the given hostname for the given domain matches the MX entry of the STS policy
# or a string describing the reason otherwise (DB error, entry not found, hostname does not match MX entry)
# return value is suiteable for use in the `event_action` directive in exim
# you should not use this function without calling mtasts_policy($domain) before
sub mtasts_valid_mx($$) {
    my ($domain, $host) = @_;

    _mtasts_debug('mtasts_valid_mx('.$domain.', '.$host.')');

    my $DB = _mtasts_db_query($domain, 0);
    if (! defined($DB)) {
        _mtasts_debug('mtasts_valid_mx('.$domain.'): returning 0: could not init DB');
        return 'do_not_connect:DB_error';
    }
    if (! $DB->{valid}) {
        _mtasts_warning('mtasts_valid_mx('.$domain.'): returning 0: no valid entry in DB');
        return 'do_not_connect:no_entry';
    }

    my @mx = @{$DB->{mx}};
    foreach my $mxhost (@mx) {
        my $mxmatch = $mxhost;
        $mxmatch =~ s/\./[.]/g;
        $mxmatch =~ s/\*/[^.]+/g;
        $mxmatch = '^'.$mxmatch.'$';
        if ($host =~ $mxmatch) {
            _mtasts_debug('mtasts_valid_mx('.$domain.', '.$host.'): returning "": host "'.$host.'" in MX list: ["'.join('", "', @mx).'"], matching mx: '.$mxhost);
            return '';
        }
    }
    _mtasts_debug('mtasts_valid_mx('.$domain.', '.$host.'): returning "do_not_connect:no_match": host "'.$host.'" NOT in MX list: ["'.join('", "', @mx).'"]');
    return 'do_not_connect:no_match';
}

# return the MX records in the policy for a given domain as a exim hostlist
# you should not use this function without calling mtasts_policy($domain) before
sub mtasts_mx_hostlist($) {
    my ($domain) = @_;

    _mtasts_debug('mtasts_mx_hostlist('.$domain.')');

    # Fail quickly if there is no database or access to the database.
    my $DB = _mtasts_db_query($domain, 0);
    if (! defined($DB)) {
        _mtasts_debug('mtasts_mx_hostlist('.$domain.'): returning "fail": could not init DB');
        return 'fail';
    }
    if (! $DB->{valid}) {
        _mtasts_warning('mtasts_mx_hostlist('.$domain.'): returning "fail": no valid entry in DB');
        return 'fail';
    }

    my @mx = @{$DB->{mx}};
    my $hostlist = join(':', @mx);

    _mtasts_debug('mtasts_mx_hostlist('.$domain.'): returning "'.$hostlist.'"');
    return $hostlist;
}


# backward compatibility
sub getmta(@) {
    _mtasts_warning('getmta() is deprecated. Please switch to mtasts_policy() resp. mtasts_valid_mx() API!');
    my ($domain, $host) = @_;
    if (int(@_) == 2) {
        return mtasts_valid_mx($domain, $host);
    }
    return mtasts_policy($domain);
}

sub getmx($) {
    _mtasts_warning('getx() is deprecated. Please switch to mtasts_mx_hostlist() API!');
    my ($domain) = @_;
    return mtasts_mx_hostlist($domain);
}


# definition of internal functions declared above
sub _mtasts_debug($) {
    my ($msg) = @_;

    if (!defined($MTASTS_DEBUG) || ($MTASTS_DEBUG eq '0')) {
        return;
    }
    # XXX:fixme: assume running in exim if stdout is not a tty
    if (-t 1) {
        print $msg."\n";
    } else {
        Exim::log_write($msg);
    }
}

sub _mtasts_warning($) {
    my ($msg) = @_;

    # XXX:fixme: assume running in exim if stderr is not a tty
    if (-t 2) {
        print STDERR 'WARNING: '.$msg."\n";
    } else {
        Exim::log_write('WARNING: '.$msg);
    }
}

sub _mtasts_sts_query($) {
    my ($domain) = @_;

    my %STS;
    # query STS for $domain
    $STS{sts} = Mail::STS->new;
    $STS{domain} = $STS{sts}->domain($domain);
    # if $domain has TLSA setting, it's using DANE, no need to go further
    eval {
        $STS{dane} = $STS{domain}->tlsa;
    };
    if ($STS{dane}) {
        return \%STS;
    }

    # analyse STS: without a usable record, id stays undefined ("0" is a valid id)
    eval {
        $STS{domain}->sts;
        my $id = $STS{domain}->sts->id;
        $STS{id} = $id if (length($id));
    };
    eval {
        $STS{rua} = $STS{domain}->tlsrpt->rua;
    };

    return \%STS;
}

sub _mtasts_sts_load_policy($) {
    my ($STS) = @_;

    my $policy;
    eval {
        $policy = $STS->{domain}->policy;
    } or do {
        $STS->{policy_fail} = 'none';
        return $STS;
    };

    eval {
        $STS->{mx}      = $policy->mx;
        $STS->{mode}    = $policy->mode;
        $STS->{max_age} = $policy->max_age;
        $STS->{policy}  = $policy->as_string;
    } or do {
        # Found some aspects of a policy, but it is badly formatted
        $STS->{policy_fail} = 'fail';
    };

    return $STS;
}

sub _mtasts_lmdb_init() {
    # load LMDB_File instead of globally in case not needed
    # to avoid errors if not installed
    use LMDB_File qw(:flags :cursor_op);
    use File::Path qw(make_path);
    my $path = $MTASTS_LMDB_PATH;

    # create the path hirachy, handle any error
    make_path($path, { error => \my $err });
    # error handling as described in LMDB_File documentation
    if ($err && @$err) {
        for my $diag (@$err) {
            my ($file, $message) = %$diag;
            if ($file eq '') {
                _mtasts_warning('_mtasts_lmdb_init(): general error: '.$message);
            } else {
                _mtasts_warning('_mtasts_lmdb_init(): problem unlinking '.$file.': '.$message);
            }
        }
        return undef;
    }

    my $env;
    eval {
        $env = LMDB::Env->new($path, { mapsize => 100 * 1024 * 1024 * 1024 });
    } or do {
        _mtasts_warning('_mtasts_lmdb_init(): could not create LMDB env: '.$LMDB_file::last_err);
        return undef;
    };

    my $transaction = $env->BeginTxn();
    if (! defined($transaction)) {
        _mtasts_warning('_mtasts_lmdb_init(): could not get LMDB transaction: '.$LMDB_file::last_err);
        return undef;
    }

    return $transaction->OpenDB({ flags => MDB_CREATE });
}

sub _mtasts_db_query($$) {
    my ($domain, $now) = @_;

    my %DB;
    my $db = _mtasts_lmdb_init();
    if (! defined($db)) {
        _mtasts_warning('_mtasts_db_query(): _mtasts_lmdb_init() failed');
        return undef;
    }
    $DB{db} = $db;

    $DB{valid} = 0;
    eval {
        $DB{expiry} = $db->get($domain.':expire');
        $DB{valid} = ($DB{expiry} > $now) ? 1 : 0;
    } or do {
        $DB{valid} = 0;
    };
    eval {
        $DB{id}     = $db->get($domain.':id');
        $DB{mode}   = $db->get($domain.':mode');
        $DB{report} = $db->get($domain.':report');
        $DB{policy} = $db->get($domain.':policy');
        # LMDB only stores strings, split MX by ':'
        my @mx = split(':', $db->get($domain.':mx'));
        $DB{mx} = \@mx;
    } or do {
        $DB{valid} = 0;
    };

    return \%DB;
}

sub _mtasts_db_save($$$$) {
    my ($DB, $domain, $STS, $now) = @_;

    $DB->{db}->put($domain.':expire', $STS->{max_age}+$now,  MDB_NODUPDATA);
    $DB->{db}->put($domain.':id',     $STS->{id},            MDB_NODUPDATA);
    $DB->{db}->put($domain.':mode',   $STS->{mode},          MDB_NODUPDATA);
    $DB->{db}->put($domain.':report', $STS->{rua},           MDB_NODUPDATA);
    $DB->{db}->put($domain.':policy', $STS->{policy},        MDB_NODUPDATA);
    # LMDB only stores strings, join MX array by ':'
    my $mx = join(':', @{$STS->{mx}});
    $DB->{db}->put($domain.':mx', $mx, MDB_NODUPDATA);

    $DB->{db}->Txn->commit;
}
