#!/bin/sh
set -e

# Defensive self-heal: on some deploy platforms the image that gets built and
# the image that actually gets run can end up out of sync (a stale/corrupted
# registry layer), which can leave the ODBC driver registered in odbcinst.ini
# but missing from disk. If that's happened, reinstall it before starting.
if ! ls /opt/microsoft/msodbcsql18/lib64/libmsodbcsql-*.so.* >/dev/null 2>&1; then
    echo "WARNING: ODBC driver file missing at container startup — reinstalling..." >&2
    apt-get update
    ACCEPT_EULA=Y apt-get install -y --reinstall --no-install-recommends msodbcsql18 unixodbc-dev
    ls /opt/microsoft/msodbcsql18/lib64/libmsodbcsql-*.so.*
    echo "ODBC driver reinstalled successfully." >&2
fi

exec "$@"
