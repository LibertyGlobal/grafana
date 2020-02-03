#!/bin/sh

DIR=`dirname $0`
cd "${DIR}" || exit 1

set -x
set -e

# git ff
git ff --tags

git co -f testing
git rsth v6.0.2

# LDAP teams
git cp origin/6.0-ldap-teams

# Rizzo OAuth
git cp origin/6.0-rizzo-oauth

# Flapping alerts
git cp origin/6.0-flapping

# Pushover notification url fix
git cp origin/6.0-pushover

# Slack image upload fix
git cp origin/6.0-slack

# Generic legend sorting
git cp origin/6.0-legend

# Add percentiles to legend
# git cp lgi/percentiles

# Per alert type notification control
git cp origin/6.0-notifications

# Datasource access and security
# git cp origin/6.0-datasource-security

# Proxy for datasources
# git cp origin/6.0-datasource-proxy

# Add ssl client certificates for ldap
git cp origin/6.0-ssl

# Add user audit
# git cp origin/6.0-user-audit

# Add all datasource features
git cp origin/6.0-datasource-features

# Add API key audit
git cp origin/6.0-apikey-track

# Add ES7 support
git cp origin/6.0-elasticsearch7

# Add feathures for Dashboards (use only after ES7 support)
# Skip ES7 to ES6
git cp origin/6.0-dashboard-features2-prepare
# Update dashboard for datasources + ES7 fix
git cp origin/6.0-dashboard-features2

#git pp origin testing:testing
