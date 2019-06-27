#!/bin/sh

DIR=`dirname $0`
cd "${DIR}" || exit 1

git ff
git ff --tags

git co -f stable
git rsth v6.0.1

git cp lgi/ldap-teams-v6.0.0
git cp lgi/percentiles
git cp lgi/flapping
git cp lgi/pushover
git cp lgi/slack-url
git cp lgi/legend_sort

git cp lgi/alerting-notification
