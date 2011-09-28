#!/usr/bin/env python
"""
GDS Burp Suite API Structures

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


class CaseInsensitiveDict(dict):
    """Case-insensitive Dictionary

    For example, ``headers['content-encoding']`` will return the
    value of a ``'Content-Encoding'`` response header."""

    @property
    def lower_keys(self):
        if not hasattr(self, '_lower_keys') or not self._lower_keys:
            self._lower_keys = dict((k.lower(), k) for k in self.iterkeys())
        return self._lower_keys

    def _clear_lower_keys(self):
        if hasattr(self, '_lower_keys'):
            self._lower_keys.clear()

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self._clear_lower_keys()

    def __delitem__(self, key):
        dict.__delitem__(self, key)
        self._lower_keys.clear()

    def __contains__(self, key):
        return key.lower() in self.lower_keys

    def __getitem__(self, key):
        # We allow fall-through here, so values default to None
        if key in self:
            return dict.__getitem__(self, self.lower_keys[key.lower()])

    def get(self, key, default=None):
        if key in self:
            return self[key]
        else:
            return default
