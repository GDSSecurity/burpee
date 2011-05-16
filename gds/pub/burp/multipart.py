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

