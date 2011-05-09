#!/usr/bin/env python
"""
GDS Burp Suite Log Parser

* Burp and Burp Suite are trademarks of PortSwigger Ltd.
Copyright 2008 PortSwigger Ltd. All rights reserved.
See http://portswigger.net for license terms.

Copyright (c) 2009-2010 Marcin Wielgoszewski <marcinw@gdssecurity.com>
Gotham Digital Science

This file is part of GDS Burp API.

GDS Burp API is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

GDS Burp API is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GDS Burp API.  If not, see <http://www.gnu.org/licenses/>
"""
from gds.pub.burp import Burp
import datetime
import logging
import os
import re

CRLF = "\r\n"
DELIMITER = "%s%s" % ('=' * 54, CRLF)
CRLF_DELIMITER = CRLF + DELIMITER
HEADER = re.compile('(\d{1,2}:\d{2}:\d{2} (AM|PM))[ \t]+(\S+)([ \t]+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|unknown host)\])?')


LOGGER = logging.getLogger(__name__)


def forward_buffer(buf, pos, n, token):
    """
    Advance buf from current position by n bytes while buf is not equal
    to token.

    @param buffer: String
    @param pos: Integer of current position in buffer.
    @param n: Length of token string.
    @param token: Token to advance current buffer position to.
    @return: Position of buffer at token.
    @rtype: int
    """
    while buf[pos:pos + n] != token:
        pos += 1

    return pos


def parse(burp_log):
    """
    Parses a Burp Suite log file.  Returns a list of Burp objects
    in the order in which they were written.

    @param burp_log: A filename or string of a Burp Suite log.
    @return: list of gds.burp.Burp objects.
    @rtype: list
    """

    if burp_log in os.listdir('.'):
        burp_file = None
        try:
            if os.path.isfile(burp_log):
                LOGGER.debug("Attempting to read from %r", burp_log)
                burp_file = open(burp_log, 'rb')
                buf = burp_file.read()

        except IOError:
            LOGGER.exception("Exception occured trying to read %r", burp_log)
            return None

        except TypeError:
            LOGGER.exception("Exception occured trying to read %r", burp_log)

        finally:
            if burp_file is not None:
                burp_file.close()

    elif hasattr(burp_log, 'read'):
        try:
            LOGGER.debug("Attempting to read from %r", burp_log)
            buf = burp_log.read()
        except:
            LOGGER.exception("Exception occured trying to read from type: %r",
                             type(burp_log))
            return None

    elif isinstance(burp_log, basestring):
        LOGGER.debug("Argument passed appears to be the burp log as a string")
        buf = burp_log

    LOGGER.debug("Parsing started at %s", datetime.datetime.now().isoformat())

    parsed = []
    history = 'START'

    pos = 0
    req = 0

    buf_len = len(buf)

    while pos < buf_len + 1:
        try:
            if history == "START":
                if buf[pos:pos + 56] == DELIMITER:
                    history = "HEADER"
                else:
                    pos += 1

            # Parse the header lines
            if history == "HEADER":
                start = pos

                # First check to make sure we've got a header block
                pos += 56
                pos = forward_buffer(buf, pos, 2, CRLF)

                header = buf[start + 56:pos]

                # Advance over CRLF
                pos += 2

                if buf[start:start + 56] == DELIMITER and \
                    buf[pos:pos + 56] == DELIMITER:

                    # we are positive this is a header and not just a
                    # coincidence that the delimiter was in the body.

                    matched = HEADER.match(header)
                    ctime, host, ip_address = matched.group(1, 3, 5)
                    burp = {}
                    burp = {'time': ctime, 'host': host,
                            'ip_address': ip_address}
                    history = "REQUEST"
                else:
                    history = "START"

            elif history == "REQUEST":
                start = pos
                pos += 56
                pos = forward_buffer(buf, pos, 2, CRLF)

                method, path, version = buf[start + 56:pos].split()

                start = pos
                pos = forward_buffer(buf, pos, 4, CRLF + CRLF)

                headers = buf[start:pos]

                # Advance over CRLF
                pos += 4
                start = pos
                pos = forward_buffer(buf, pos, 56, DELIMITER)

                # at this point, we're right at the delimiter, so -2 bytes
                # to account for that last CRLF.
                body = buf[start:pos - 2]

                # we got the body, now advance over the delimiter
                pos += 56

                burp['request'] = {'method': method, 'path': path,
                    'version': version, 'headers': headers, 'body': body}

                history = "RESPONSE"

            if history == "RESPONSE":
                start = pos

                pos = forward_buffer(buf, pos, 2, CRLF)

                # slice buf from index of current position + 3 CRLF
                # to current position + 3 CRLF + delimiter length (= 62)
                if buf[pos + 6:pos + 62] != DELIMITER:

                    headerline = buf[start:pos].split(' ', 2)
                    len_headerline = len(headerline)

                    if len_headerline == 3:
                        resp_version, resp_status, resp_reason = headerline
                    elif len_headerline == 2:
                        resp_version, resp_status = headerline
                        resp_reason = ""
                    elif len_headerline == 1 and headerline[0] == '':
                        resp_version = None
                        resp_status = 0
                        resp_reason = None

                    start = pos
                    pos = forward_buffer(buf, pos, 4, CRLF + CRLF)

                    resp_headers = buf[start:pos]

                    # Advance over CRLF
                    pos += 4
                    start = pos

                    while buf[pos - 2:pos + 56] != CRLF_DELIMITER and \
                        pos < buf_len - 2:
                        pos += 1

                    resp_body = buf[start:pos]

                    burp['response'] = {'version': resp_version,
                        'status': resp_status, 'reason': resp_reason,
                        'headers': resp_headers, 'body': resp_body}

                    pos += 56

                    resp_version = None
                    resp_status = 0
                    resp_reason = resp_body = resp_headers = None

                else:
                    burp['response'] = {'version': None, 'status': 0,
                        'reason': None, 'headers': None, 'body': ''}

                req += 1
                parsed.append(Burp(burp, req))
                history = "START"

                burp = {}

        # The most likely cause for an exception to get raised is if
        # modifications were made to the main Burp class and weren't handled
        # correctly.  Check your source!
        #
        # If this is a legit exception due to incorrect parsing, please send
        # labs@gdssecurity.com an email with the error message and if possible
        # a sanitized proxy log.
        except:
            LOGGER.exception("Parsing exception occurred at index/pos: %d/%d",
                             req, pos)
            pos += 1

    LOGGER.debug("Parsing completed at %s", datetime.datetime.now().isoformat())
    return parsed

