#!/usr/bin/env python
"""
GDS Burp Suite API Utilities

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
import cgi
import logging
import cPickle
import gzip
import hashlib
import hmac
import json
import re

# compile regular expression to match multipart form parameters
BOUNDARY = re.compile('Content-Disposition: form-data; name="([^"]+)', re.I)
FORM_DATA = re.compile('multipart/form-data; boundary=([a-z0-9\-]+)', re.I)

KEY = 'gds.burp'
LOGGER = logging.getLogger(__name__)


def parse_parameters(request):
    """
    Parse request parameters in a gds.burp.Burp request/response object.

    @param request: A gds.burp.Burp request/response object.
    @return: A dict containing parameters and values from query string,
    body and multipart/form-data.
    @rtype: dict
    """
    parameters = {}

    if request.url.query:
        parameters['query'] = dict(cgi.parse_qsl(request.url.query))

    content_type = request.get_request_header('Content-Type')

    if 'amf' in content_type.lower():
        # Don't even try to parse a binary AMF request
        return

    elif 'multipart/form-data' in content_type.lower():
        boundary = re.search(FORM_DATA, content_type).group(1)
        params = parse_multipart_form(request.get_request_body(), boundary)
        parameters['multipart_form'] = params

    elif 'json' in content_type.lower():
        parameters['json'] = json.loads(request.get_request_body())

    elif request.get_request_body():
        parameters['body'] = dict(cgi.parse_qsl(request.get_request_body()))

    return parameters


def parse_multipart_form(content, multipart_boundary):
    """
    Parses multipart/form-data.

    This needs more testing, as I'm not sure all browsers make multipart form
    requests that are in this format.

    @param content: The multipart/form-data content from HTTP request.
    @param multipart_boundary: The boundary specifier as declared in the HTTP
    Content-Type: multipart/form-data header.
    @return: A dict containing parameters and values.
    @rtype: dict
    """
    # each boundary is prefixed by two dashes
    multipart_boundary = '--' + multipart_boundary

    # snip leading boundary and trailing boundaries
    post = content.split(multipart_boundary)[1:-1]

    # match the name parameter against each multipart form boundary in post
    params = [BOUNDARY.search(param).group(1) for param in post]

    # strip the first part of the form boundary preceding the two CRLF's
    # remove any trailing whitespace from the multipart form parameter value
    values = [value.split('\r\n\r\n', 1)[1].rstrip() for value in post]

    return dict(zip(params, values))


def parse_headers(headers):
    """
    Parse HTTP headers.

    @param headers: A string of HTTP headers.
    @return: A dict of HTTP headers and values.
    @rtype: dict
    """
    if not headers:
        return {}

    processed_headers = {}

    try:
        header_values = [h.split(':', 1) for h in headers.strip().split('\r\n')]

        for header, value in header_values:
            header = header.title().strip()
            #value = safeint(value)
            value = value.strip()

            prev = processed_headers.get(header)

            if prev is None:
                processed_headers[header] = value
            elif prev != value:
                #processed_headers[header] += ", " + value
                try:
                    processed_headers[header].append(value)
                except AttributeError:
                    processed_headers[header] = [prev, value]
            else:
                # We've already seen this header and value...
                # don't process duplicates
                continue

    # request may not always have a corresponding response object,
    # thus just continue processing
    except AttributeError:
        pass

    return processed_headers


def safeint(num):
    """
    If possible, cast an object of type String, Float, Boolean to an Integer.
    Returns int(num) if successful, else num.

    @param num: An arbitrary type to be cast as an int.
    @return: Attempt to return int(num).  Return num if failed.
    """
    try:
        return int(num)
    except TypeError:
        return num
    except ValueError:
        return num.strip()


def save_state(filename, parsed_burp_log):
    """
    Used to save a parsed Burp Suite log to file that can later be re-loaded.

    @param parsed_burp_log: A Burp Suite log parsed by gds.burp.log.parse().
    @param filename: Name of file to save a parsed Burp Suite log state to.
    """
    dump = cPickle.dumps(parsed_burp_log)

    # Append an HMAC to pickled string.
    state = dump + hmac.new(KEY, dump, hashlib.sha1).digest()

    try:
        gzf = gzip.open(filename, 'wb')
        gzf.write(state)
        gzf.close()
        LOGGER.debug("Saved state to " + filename)
    except IOError, e:
        LOGGER.error("Could not save to %s (%s)" + (filename, e))
        return


def load_state(filename):
    """
    Load a previously parsed Burp Suite log.

    Due to security concerns regarding the Python Pickle module, this method
    will only only load pickled objects that were saved using
    gds.burp.save_state().

    @param filename: The filename of the gds.burp state file.
    @return: A parsed Burp Suite log.
    @rtype: list
    """
    LOGGER.debug("Loading state from " + filename)

    try:
        gzf = gzip.open(filename, 'rb')
        state = gzf.read()
        gzf.close()
    except IOError, e:
        LOGGER.error("%s: %s" % (e, filename))
        return

    # A sha1 digest is 20 bytes.
    dump, mac = state[:-20], state[-20:]

    # Validate the HMAC at the end of the pickled string to provide
    # limited validation the object was not tampered with.  The threat
    # we're trying to address by validating the HMAC is the scenario where
    # the user specified an incorrect state file or it has been modified by
    # another program, so that it doesn't blow up in their face when they do.
    #
    # This doesn't prevent someone from reversing how we generated the MAC
    # and creating their own malicious object that is later unpickled.
    #
    # Overkill for this?  yes.. but I like it.

    if is_equal(hmac.new(KEY, dump, hashlib.sha1).digest(), mac):
        parsed = cPickle.loads(dump)
        LOGGER.debug("Loaded state from " + filename)
        return parsed

    else:
        LOGGER.error("Incorrect checksum while loading state from " + filename)
        raise cPickle.UnpicklingError("Incorrect checksum while loading state")


def is_equal(original, supplied):
    """
    A byte for byte string comparison function.  Usually used when comparing
    two HMAC's, it returns True or False only after the entire string was
    analyzed (meaning, we don't return False on the first non-match).

    If use this for validating passwords, you're doing it wrong.

    @param original: The original string to be compared against.
    @param supplied: A string supplied by the user.
    @return: True if value of original is equal to value of supplied.
    @rtype: bool
    """
    result = 0

    # We don't know the implementation details of zip() function used later,
    # so lets return False early if the lengths of both do not match.  Since
    # this function is used to compare two HMAC's, it doesn't matter if we
    # return early and thus "leak" the length of the HMAC.
    if len(original) != len(supplied):
        return False

    for x, y in zip(map(ord, original), map(ord, supplied)):
        result |= x ^ y

    return result == 0
