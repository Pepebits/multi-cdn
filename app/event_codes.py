"""Stable codes for the history events that code reacts to.

The summary is translated text meant for people: matching it (by prefix, in every language) breaks
as soon as a catalog is reworded. Events that the notifier or the restart logic must recognise
carry one of these codes in the `events.code` column instead.
"""

BLOCK_START = "block_start"        # a domain's Cloudflare IPs became blocked at some ISP
BLOCK_END = "block_end"            # ...and are no longer blocked
GCORE_PREPARED = "gcore_prepared"  # first preparation of a domain on Gcore
CERT_RENEWED = "cert_renewed"      # automatic renewal of the Gcore certificate
LOGIN_LOCKED = "login_locked"      # sign-in blocked after too many failed attempts
WEEKLY_SUMMARY = "weekly_summary"  # Monday summary of the last 7 days (app/summary.py)
