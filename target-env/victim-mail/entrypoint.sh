#!/bin/sh
# target-env/victim-mail/entrypoint.sh
#
# Postfix mynetworks must match the lab subnet, which is parameterized per
# student via LAB_NET_PREFIX (Phase 0 isolation). The Dockerfile previously
# baked `172.20.0.0/24` into the image, breaking any student whose lab-net
# prefix differs. Resolved by deferring config to container start.
set -eu

LAB_SUBNET="${LAB_NET_PREFIX:-172.20.0}.0/24"

postconf -e "myhostname = victim-mail.lab.local"
postconf -e "mydomain = lab.local"
postconf -e "mynetworks = ${LAB_SUBNET} 127.0.0.0/8"
postconf -e "inet_interfaces = all"
postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination"
postconf -e "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination"

echo "[victim-mail] mynetworks set to ${LAB_SUBNET} 127.0.0.0/8"

exec "$@"
