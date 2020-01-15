#!/bin/sh

DIR=`dirname $0`
cd "${DIR}" || exit 1

set -x
set -e

# git ff
git ff --tags

git co -f testing
git rsth v6.5.2

# LDAP teams
git cp origin/6.5-ldap-teams

# Rizzo OAuth
git cp origin/6.5-rizzo-oauth

# Flapping alerts
git cp origin/6.5-flapping

# Generic legend sorting
git cp origin/6.5-legend

# Per alert type notification control
git cp origin/6.5-notifications

# Add ssl client certificates for ldap
git cp origin/6.5-ssl

# Add all datasource features
git cp origin/6.5-datasource-features

# Add API key audit
git cp origin/6.5-apikey-track

git cp origin/6.5-dashboard-features

#git pp origin testing:testing

