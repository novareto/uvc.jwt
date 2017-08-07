# -*- coding: utf-8 -*-

import datetime
from pytz import timezone


def now(tz=None):
    if tz is None:
        tz = timezone('Europe/Berlin')
    return datetime.datetime.now(tz)


def expiration_date(minutes=600, tz=None):
    if tz is None:
        tz = timezone('Europe/Berlin')
    dt = now(tz) + datetime.timedelta(minutes=minutes)
    return dt


def get_posix_timestamp(dt):
    # utc time = local time - utc offset
    utc_naive  = dt.replace(tzinfo=None) - dt.utcoffset()
    timestamp = (utc_naive - datetime.datetime(1970, 1, 1)).total_seconds()
    return timestamp


def date_from_timestamp(ts, tz=None):
    if tz is None:
        tz = timezone('Europe/Berlin')
    return datetime.datetime.fromtimestamp(ts, tz=tz)
