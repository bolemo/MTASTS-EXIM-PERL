#!/usr/bin/python3

import sys
import os
import fcntl
import lmdb

lmdb_path = sys.argv[1]

# mta-lmdb.pl opens the DB with MDB_NOLOCK: share its lock file while reading
with open(os.path.join(lmdb_path, 'write.lock'), 'a') as lockfile:
    fcntl.flock(lockfile, fcntl.LOCK_SH)
    env = lmdb.open(lmdb_path, max_dbs=10, readonly=True, lock=False)
    db = env.open_db()

    with env.begin() as txn:
        entries = list(txn.cursor(db=db))[1:]

for key, value in entries:
    k, v = key.decode(), value.decode()
    print('%s="%s"' % (k, v))
