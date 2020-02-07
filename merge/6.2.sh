#!/bin/sh

DIR=`dirname $0`
cd "${DIR}" || exit 1

set -x
set -e

# git ff
git ff --tags

git co -f testing
git rsth v6.2.5

# LDAP teams
git cp origin/6.2-ldap-teams

# Flapping alerts
git cp origin/6.2-flapping

# Pushover notification url fix
git cp origin/6.2-pushover

# Slack image upload fix
git cp origin/6.2-slack

# Generic legend sorting
git cp origin/6.2-legend

# Per alert type notification control
git cp origin/6.2-notifications

# Datasource access and security
git cp origin/6.2-datasource-security

# Proxy for datasources
git cp origin/6.2-datasource-proxy

# Add ssl client certificates for ldap
git cp origin/6.2-ssl

# Block phantomjs binary
git cp origin/6.2-phantomjs 

#git pp origin testing:testing
