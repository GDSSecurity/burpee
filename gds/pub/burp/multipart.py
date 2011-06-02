#!/usr/bin/env python
"""
GDS Burp Suite API

* Burp and Burp Suite are trademarks of PortSwigger Ltd.
Copyright 2008 PortSwigger Ltd. All rights reserved.
See http://portswigger.net for license terms.

Copyright (c) 2009-2011 Marcin Wielgoszewski <marcinw@gdssecurity.com>
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
from .utils import CRLF
from urllib import quote_plus


class HTMLMultipartForm(object):
    def __init__(self, boundary, *params):
        self.boundary = boundary
        self.params = params

    def __iter__(self):
        for param in self.params:
            yield param

    def as_string(self):
        msg = self.boundary
        for param in self:
            msg +=  CRLF + param.as_string(boundary=self.boundary)
        return msg + '--' + CRLF

    def as_list(self):
        return list(self.params)

    def to_urlencoded(self, encode_params=True):
        qs = ""
        for p in self:
            if encode_params:
                qs += "%s=%s" % (quote_plus(p.name), quote_plus(p.value))
            else:
                qs += "%s=%s" % (p.name, p.value)
        return qs



class HTMLMultipartParam(object):
    def __init__(self, name, params, headers, value):
        self.name = name
        self.value = value
        self.params = {}
        self.headers = {}

        if isinstance(params, dict):
            self.params.update(params)
        if isinstance(headers, dict):
            self.headers.update(headers)

    def as_string(self, boundary=None):
        msg = 'Content-Disposition: form-data; name="%s"' % self.name
        for k, v in self.params.iteritems():
            msg += '; %s="%s"' % (k, v)
        msg += CRLF
        for k, v in self.headers.iteritems():
            msg += "%s: %s" % (k, v)
        msg += CRLF
        if isinstance(self.value, HTMLMultipartForm):
            msg += self.value.as_string()
        else:
            msg += self.value
        if boundary:
            msg += CRLF + boundary

        return msg

