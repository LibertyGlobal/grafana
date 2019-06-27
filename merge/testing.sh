#!/bin/sh

DIR=`dirname $0`
cd "${DIR}" || exit 1

git ff
git ff --tags

git co -f testing
git rsth v6.2.2

git cp lgi/ldap-teams-v6.2.1
git cp lgi/flapping
git cp lgi/pushover
git cp lgi/slack-url
git cp lgi/legend_sort
# git cp lgi/percentiles
git cp lgi/alerting-notification-6.2.1
git cp lgi/phantomjs-fix

# git m lgi/template-filter
# git m lgi/datasource-teams

git m -m "Merge datasource access patches" lgi/datasource-access

