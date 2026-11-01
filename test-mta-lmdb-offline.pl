#!/usr/bin/perl

# Offline regression tests for mta-lmdb.pl: Mail::STS is replaced by the stub
# below, so neither DNS nor HTTPS are used. Run it from this directory, as a
# normal user. Needs LMDB_File and DateTime.

use strict;
use Fcntl qw(:flock);
use File::Temp qw(tempdir);
use POSIX qw(_exit);
use Test::More;

our $MTASTS_DEBUG = 0;
our $MTASTS_LMDB_PATH;

# what the stub answers per domain: id is the TXT record's id (none: no record),
# policy is the HTTPS answer (none: fetch fails, broken: badly formatted)
our %LIVE;
our @WARNINGS;

BEGIN { $INC{'Mail/STS.pm'} = __FILE__; }

package Mail::STS;
sub new { return bless({}, shift); }
sub domain { return bless({ name => $_[1] }, 'Mail::STS::Domain'); }

package Mail::STS::Domain;
sub _live { return $main::LIVE{$_[0]->{name}} || {}; }
sub tlsa { return undef; }
sub tlsrpt { return bless({}, 'Mail::STS::TLSRPTRecord'); }
sub sts {
    my $id = $_[0]->_live->{id};
    defined($id) or die("no TXT record\n");
    return bless({ id => $id }, 'Mail::STS::STSRecord');
}
sub policy {
    my $policy = $_[0]->_live->{policy};
    defined($policy) or die("no policy\n");
    return bless($policy, 'Mail::STS::Policy');
}

package Mail::STS::STSRecord;
sub id { return $_[0]->{id}; }

package Mail::STS::TLSRPTRecord;
sub rua { return 'mailto:tlsrpt@example.org'; }

package Mail::STS::Policy;
sub _get { $_[0]->{broken} and die("badly formatted\n"); return $_[0]->{$_[1]}; }
sub mx { return $_[0]->_get('mx'); }
sub mode { return $_[0]->_get('mode'); }
sub max_age { return $_[0]->_get('max_age'); }
sub as_string { return 'version: STSv1'; }

package Exim;
sub log_write { push(@main::WARNINGS, $_[0]); }

package main;

my $tmp = tempdir(CLEANUP => 1);
# not a tty anymore: _mtasts_warning() uses the Exim::log_write() above
open(STDERR, '>', "$tmp/stderr") or die("stderr: $!");

# like exim
umask(0);

$MTASTS_LMDB_PATH = "$tmp/missing/dir";
do './mta-lmdb.pl';
die("mta-lmdb.pl: $@") if ($@);

sub live_policy {
    my ($id, $mode, $mx, $max_age) = @_;
    return { id => $id, policy => { mode => $mode, mx => [$mx], max_age => $max_age // 86400 } };
}

# ----- the LMDB directory is recreated when it is missing
$LIVE{'nosts.example'} = {};
is(mtasts_policy('nosts.example'), 'none', 'missing DB directory: no "fail" without MTA-STS');
$LIVE{'new.example'} = live_policy('1', 'enforce', 'mx.new.example');
is(mtasts_policy('new.example'), 'enforce', 'missing DB directory: policy is loaded');
ok(-e "$MTASTS_LMDB_PATH/data.mdb", 'missing DB directory: created by the first write');
is((stat("$MTASTS_LMDB_PATH/data.mdb"))[2] & 0777, 0660, 'missing DB directory: group can use the DB');
is((stat($MTASTS_LMDB_PATH))[2] & 0777, 0770, 'missing DB directory: group can use the directory');
is(mtasts_valid_mx('new.example', 'mx.new.example'), '', 'missing DB directory: policy is cached');
is_deeply(\@WARNINGS, [], 'missing DB directory: no warning');

# ----- policy ids are strings
for my $ids (['abc123', 'def456'], ['20260101T000000', '20260101T120000']) {
    my ($old, $new) = @$ids;
    $LIVE{'id.example'} = live_policy($old, 'enforce', "mx-$old.id.example");
    is(mtasts_policy('id.example'), 'enforce', "id $old: first policy");
    $LIVE{'id.example'} = live_policy($new, 'testing', "mx-$new.id.example");
    is(mtasts_policy('id.example'), 'testing', "id $old changed to $new: policy reloaded");
    is(mtasts_valid_mx('id.example', "mx-$new.id.example"), '', "id $new: new MX accepted");
}

# ----- a valid cached policy applies without a live one (RFC 8461 section 3.3)
$LIVE{'cache.example'} = live_policy('1', 'enforce', 'mx.cache.example', 5);
is(mtasts_policy('cache.example'), 'enforce', 'cache: first policy');
$LIVE{'cache.example'} = {};
is(mtasts_policy('cache.example'), 'enforce', 'cache: TXT record gone');
$LIVE{'cache.example'} = { id => '2' };
is(mtasts_policy('cache.example'), 'enforce', 'cache: new id, HTTPS fetch fails');
$LIVE{'cache.example'} = { id => '2', policy => { broken => 1 } };
is(mtasts_policy('cache.example'), 'enforce', 'cache: new id, badly formatted policy');
sleep(6);
$LIVE{'cache.example'} = {};
is(mtasts_policy('cache.example'), 'none', 'cache expired: TXT record gone');
$LIVE{'cache.example'} = { id => '2' };
is(mtasts_policy('cache.example'), 'none', 'cache expired: new id, HTTPS fetch fails');

# ----- an unusable policy is handled as no policy (RFC 8461 section 3.3) and is not cached
for my $case (['no mx', { mode => 'enforce', mx => [], max_age => 86400 }],
              ['no max_age', { mode => 'enforce', mx => ['mx.bad.example'] }],
              ['badly formatted', { broken => 1 }]) {
    my ($name, $policy) = @$case;
    $LIVE{'bad.example'} = { id => '1', policy => { %$policy } };
    is(mtasts_policy('bad.example'), 'none', "$name: policy none");
    is(mtasts_valid_mx('bad.example', 'mx.bad.example'), 'do_not_connect:no_entry', "$name: not cached");
}
$LIVE{'kept.example'} = live_policy('1', 'enforce', 'mx.kept.example');
is(mtasts_policy('kept.example'), 'enforce', 'unusable policy: first a good one');
$LIVE{'kept.example'} = { id => '2', policy => { mode => 'enforce', mx => [], max_age => 86400 } };
is(mtasts_policy('kept.example'), 'enforce', 'unusable policy: cached one still applied');
is(mtasts_valid_mx('kept.example', 'mx.kept.example'), '', 'unusable policy: cached MX kept');
$LIVE{'modenone.example'} = { id => '1', policy => { mode => 'none', mx => [], max_age => 86400 } };
is(mtasts_policy('modenone.example'), 'none', 'mode none without mx: accepted');
ok(_mtasts_db_query('modenone.example', time())->{valid}, 'mode none without mx: cached');

# ----- "0" is a valid policy id, an empty one is not
$LIVE{'zero.example'} = live_policy('0', 'enforce', 'mx.zero.example');
is(mtasts_policy('zero.example'), 'enforce', 'id 0: policy applied');
is(mtasts_valid_mx('zero.example', 'mx.zero.example'), '', 'id 0: policy cached');
$LIVE{'zero.example'} = live_policy('0', 'testing', 'mx.zero.example');
is(mtasts_policy('zero.example'), 'enforce', 'id 0 unchanged: policy from the DB');
$LIVE{'emptyid.example'} = live_policy('', 'enforce', 'mx.emptyid.example');
is(mtasts_policy('emptyid.example'), 'none', 'empty id: handled as no record');

# ----- TLS-Report-Submitter
$LIVE{'report.example'} = live_policy('1', 'enforce', 'mx.report.example');
is(mtasts_policy('report.example', 'example.org'), 'none', 'submitter given: policy none');
is(mtasts_policy('report.example', ''), 'enforce', 'submitter empty: normal policy');
is(mtasts_policy('report.example'), 'enforce', 'submitter omitted: normal policy');

# ----- an empty domain, what exim gives without multi_domain = false
@WARNINGS = ();
is(mtasts_valid_mx('', 'mx.report.example'), 'do_not_connect:no_entry', 'empty $domain: no connection');

# ----- locking: readers and writers exclude each other, readers do not
sub child_finishes_while_locked {
    my ($mode, $code) = @_;
    # forked before locking: a child inheriting the lock's file handle would keep it held
    pipe(my $go_read, my $go_write) or die("pipe: $!");
    my $pid = fork();
    if (! $pid) {
        close($go_write);
        <$go_read>;
        $code->();
        _exit(0);
    }
    close($go_read);
    my $lockfh = _mtasts_db_lock($mode, 5);
    close($go_write);
    select(undef, undef, undef, 1);
    my $finished = (waitpid($pid, POSIX::WNOHANG) == $pid);
    close($lockfh);
    waitpid($pid, 0) if (! $finished);
    die("child failed: $?") if ($? != 0);
    return $finished;
}
my $save = sub {
    _mtasts_db_save('lock.example', { max_age => 60, id => '1', mode => 'enforce', mx => ['mx.lock.example'] }, time());
};
my $query = sub { _mtasts_db_query('lock.example', time()); };
ok(! child_finishes_while_locked(LOCK_EX, $query), 'reader waits for a writer');
ok(! child_finishes_while_locked(LOCK_SH, $save), 'writer waits for a reader');
ok(child_finishes_while_locked(LOCK_SH, $query), 'readers do not wait for each other');

# ----- the lock needs no write access to the file
SKIP: {
    skip('running as root', 3) if ($> == 0);
    @WARNINGS = ();
    chmod(0444, "$MTASTS_LMDB_PATH/write.lock");
    ok(! child_finishes_while_locked(LOCK_SH, $save), 'read-only lock file: locks still exclude each other');
    my $DB = _mtasts_db_query('new.example', time());
    chmod(0666, "$MTASTS_LMDB_PATH/write.lock");
    ok($DB->{valid}, 'read-only lock file: reading works');
    is_deeply(\@WARNINGS, [], 'read-only lock file: no warning');
}

# ----- reading goes on when the lock cannot be taken
SKIP: {
    skip('running as root', 2) if ($> == 0);
    @WARNINGS = ();
    chmod(0, "$MTASTS_LMDB_PATH/write.lock");
    my $DB = _mtasts_db_query('new.example', time());
    chmod(0666, "$MTASTS_LMDB_PATH/write.lock");
    ok($DB->{valid}, 'lock file unusable: reading still works');
    is(scalar(@WARNINGS), 1, 'lock file unusable: one warning');
}

# ----- a stuck holder of the lock does not stop mail: reading goes on, waiting has an end
{
    pipe(my $go_read, my $go_write) or die("pipe: $!");
    my $pid = fork();
    if (! $pid) {
        close($go_write);
        <$go_read>;
        @WARNINGS = ();
        my $DB = _mtasts_db_query('new.example', time());
        my $read_ok = ($DB->{valid} && (scalar(@WARNINGS) == 1));
        my $lock_given_up = (! defined(_mtasts_db_lock(LOCK_EX, 1)));
        _exit(($read_ok && $lock_given_up) ? 0 : 1);
    }
    close($go_read);
    my $lockfh = _mtasts_db_lock(LOCK_EX, 5);
    close($go_write);
    waitpid($pid, 0);
    is($?, 0, 'lock held for too long: reader goes on with a warning, waiting has an end');
    close($lockfh);
}

# ----- an empty DB file, as seen while the first write creates it, is left alone
{
    my $path = $MTASTS_LMDB_PATH;
    $MTASTS_LMDB_PATH = "$tmp/empty";
    mkdir($MTASTS_LMDB_PATH);
    open(my $empty, '>', "$MTASTS_LMDB_PATH/data.mdb") or die("data.mdb: $!");
    close($empty);
    ok(! _mtasts_db_query('new.example', time())->{valid}, 'empty DB file: nothing cached');
    is(-s "$MTASTS_LMDB_PATH/data.mdb", 0, 'empty DB file: not written by a reader');
    $MTASTS_LMDB_PATH = $path;
}

# ----- smoke test: concurrent writers and readers run without any error. LMDB's
# snapshots hide partial entries even without our lock, the tests above check that one.
# Readers pause: flock is not fair, readers in a tight loop would starve the writers.
@WARNINGS = ();
my $end = time() + 5;
my @pids;
for my $writer (1 .. 2) {
    my $pid = fork();
    if (! $pid) {
        my $n = 0;
        while (time() < $end) {
            my $id = $writer.'x'.$n++;
            _mtasts_db_save('stress.example', { max_age => 60, id => $id, mode => 'enforce', mx => ["mx$id.example"] }, time());
        }
        _exit(@WARNINGS ? 1 : 0);
    }
    push(@pids, $pid);
}
for my $reader (1 .. 8) {
    my $pid = fork();
    if (! $pid) {
        my $bad = 0;
        while (time() < $end) {
            my $DB = eval { _mtasts_db_query('stress.example', time()) };
            $bad++ if (! defined($DB));
            $bad++ if ($DB->{valid} && ($DB->{mx}->[0] ne 'mx'.$DB->{id}.'.example'));
            select(undef, undef, undef, 0.005);
        }
        _exit(($bad || @WARNINGS) ? 1 : 0);
    }
    push(@pids, $pid);
}
my $failed = 0;
for my $pid (@pids) {
    waitpid($pid, 0);
    $failed++ if ($? != 0);
}
is($failed, 0, 'concurrent writers and readers: no error');

done_testing();
