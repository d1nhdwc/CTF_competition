#!/bin/sh
set -e

mkdir -p /srv/medrec/data /srv/medrec/data/archive /run/medrec

[ -f /srv/medrec/data/users.db ] || : > /srv/medrec/data/users.db
chown medrec-front:medrec-front /srv/medrec/data/users.db
chmod 600 /srv/medrec/data/users.db

chown root:root /srv/medrec/data
chmod 755 /srv/medrec/data

chown medrec-rend:medrec-rend /srv/medrec/data/archive
chmod 700 /srv/medrec/data/archive

chmod 755 /run/medrec

exec /srv/medrec/medrecd
