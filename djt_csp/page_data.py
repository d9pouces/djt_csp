from html.parser import HTMLParser
from typing import Dict, List

from django.http import HttpRequest, HttpResponse, SimpleCookie

from djt_csp.checkers import CHECKED_HTTP_HEADERS, CHECKED_RESOURCES


class HeaderHTMLParser(HTMLParser):
    def __init__(self, *, convert_charrefs=True):
        super().__init__(convert_charrefs=convert_charrefs)
        self.headers = {}  # type: Dict[str, str]
        self.scripts_attributes = []  # type: List[Dict[str, str]]
        self.http_ws_resources = {
            x: [] for x in CHECKED_RESOURCES
        }  # type: Dict[str, List[str]]

    def reset(self):
        super().reset()
        self.headers = {}
        self.scripts_attributes = []
        self.http_ws_resources = {x: [] for x in CHECKED_RESOURCES}

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = {x.lower(): y for (x, y) in attrs}
        http_equiv = attrs.get("http-equiv", "").lower()
        content = attrs.get("content")
        if tag == "meta" and http_equiv in CHECKED_HTTP_HEADERS and content:
            self.headers[http_equiv] = content
        elif tag == "script":
            self.scripts_attributes.append(attrs)
        attr = CHECKED_RESOURCES.get(tag)
        origin = attrs.get(tag, "")
        if attr and (origin.startswith("http://") or origin.startswith("ws://")):
            self.http_ws_resources[tag].append(origin)

    def error(self, message):
        pass


def get_response_characteristics(request: HttpRequest, response):
    final_values = None
    content_type = ""
    if response.has_header("Content-Type"):
        content_type = response["Content-Type"]
    if (
            not content_type.startswith("text/html")
            or not isinstance(response, HttpResponse)
            or response.status_code < 200
            or (300 <= response.status_code < 400)
    ):
        pass
    else:
        response_headers = {}
        for header in CHECKED_HTTP_HEADERS:
            if header in response:
                response_headers[header] = response[header]
        parser = HeaderHTMLParser()
        try:
            parser.feed(response.content.decode())
            scripts_attributes = parser.scripts_attributes
            html_headers = parser.headers
            http_ws_resources = parser.http_ws_resources
            cookies_l = []
            cookies = response.cookies  # type: SimpleCookie
            for name, values in cookies.items():
                cookies_l.append(
                    {
                        "name": name,
                        "expires": values["expires"],
                        "path": values["path"],
                        "comment": values["comment"],
                        "domain": values["domain"],
                        "max-age": values["max-age"],
                        "secure": values["secure"],
                        "version": values["version"],
                        "httponly": values["httponly"],
                        "samesite": values["samesite"],
                    }
                )
        except AssertionError:
            scripts_attributes = None
            html_headers = None
            http_ws_resources = None
            cookies_l = None
        final_values = {
            "cookies": cookies_l,
            "html_headers": html_headers,
            "response_headers": response_headers,
            "content_type": content_type,
            "scripts_attributes": scripts_attributes,
            "http_ws_resources": http_ws_resources,
            "is_secure": request.is_secure(),
        }
    return final_values
