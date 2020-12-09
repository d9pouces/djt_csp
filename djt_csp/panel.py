# ##############################################################################
#  This file is part of djt_csp                                                #
#                                                                              #
#  Copyright (C) 2020 Matthieu Gallet <github@19pouces.net>                    #
#  All Rights Reserved                                                         #
#                                                                              #
#  You may use, distribute and modify this code under the                      #
#  terms of the (BSD-like) CeCILL-B license.                                   #
#                                                                              #
#  You should have received a copy of the CeCILL-B license with                #
#  this file. If not, please visit:                                            #
#  https://cecill.info/licences/Licence_CeCILL-B_V1-en.txt (English)           #
#  or https://cecill.info/licences/Licence_CeCILL-B_V1-fr.txt (French)         #
#                                                                              #
# ##############################################################################
import datetime
from functools import lru_cache, cached_property
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from logging import INFO, WARNING, CRITICAL, ERROR
from typing import Dict, List

import pkg_resources
from debug_toolbar.panels import Panel
from django.http import HttpResponse, HttpRequest

# noinspection PyProtectedMember
from django.template import engines, TemplateSyntaxError
from django.templatetags.static import static
from django.utils.safestring import mark_safe

from djt_csp.checkers import (
    CHECKED_RESOURCES,
    CHECKED_HTTP_HEADERS,
    Checker,
    ContentTypeSniff,
    RefererComponent,
    XSSProtection,
    FrameOptions,
    ScriptIntegrityChecker,
    CookieAnalyzer,
    CSPChecker,
    CORSChecker,
    HSTSChecker,
    HPKPChecker,
)


def template_from_string(template_string):
    """
    Convert a string into a template object,
    using a given template engine or using the default backends
    from settings.TEMPLATES if no engine was specified.
    """
    # This function is based on django.template.loader.get_template,
    for engine in engines.all():
        try:
            return engine.from_string(template_string)
        except TemplateSyntaxError:
            pass
    raise TemplateSyntaxError(template_string)


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


class SecurityPanel(Panel):
    """
    """

    name = "Security score"
    title = "Security score"
    template = "templates/debug/security_panel.html"
    has_content = True

    def generate_stats(self, request: HttpRequest, response: HttpResponse):
        content_type = ""
        if response.has_header("Content-Type"):
            content_type = response["Content-Type"]
        if (
            not content_type.startswith("text/html")
            or not isinstance(response, HttpResponse)
            or response.status_code < 200
            or (300 <= response.status_code < 400)
        ):
            return
        max_age = 365 * 24 * 60 * 60  # one year
        expires = datetime.datetime.strftime(
            datetime.datetime.utcnow() + datetime.timedelta(seconds=max_age),
            "%a, %d-%b-%Y %H:%M:%S GMT",
        )
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
        values = {
            "cookies": cookies_l,
            "html_headers": html_headers,
            "response_headers": response_headers,
            "content_type": content_type,
            "scripts_attributes": scripts_attributes,
            "http_ws_resources": http_ws_resources,
            "is_secure": request.is_secure(),
        }
        self.record_stats(values)

    @cached_property
    def components(self) -> List[Checker]:
        stats = self.get_stats()
        components = []  # type: List[Checker]
        if stats and stats.get("html_headers") is not None:
            components = [
                CSPChecker(stats),
                CookieAnalyzer(stats),
                CORSChecker(stats),
                HPKPChecker(stats),
                HSTSChecker(stats),
                RefererComponent(stats),
                ScriptIntegrityChecker(stats),
                ContentTypeSniff(stats),
                FrameOptions(stats),
                XSSProtection(stats),
            ]
        for comp in components:
            comp.load()
        return components

    def nav_subtitle(self):
        score = 100
        level = INFO
        for comp in self.components:
            level = max(comp.level, level)
            score += comp.score
        scores = [
            (100, "A+"),
            (90, "A"),
            (85, "A-"),
            (80, "B+"),
            (70, "B"),
            (65, "B-"),
            (60, "C+"),
            (50, "C"),
            (45, "C-"),
            (40, "D+"),
            (30, "D"),
            (25, "D-"),
        ]
        letter = "F"
        for score_, letter_ in scores:
            if score >= score_:
                letter = letter_
                break
        if level >= CRITICAL or score <= 44:
            img = static("admin/img/icon-no.svg")
        elif level >= ERROR or score <= 64:
            img = static("admin/img/icon-no.svg")
        elif level >= WARNING or score <= 84:
            img = static("admin/img/icon-alert.svg")
        else:
            img = static("admin/img/icon-yes.svg")
        return mark_safe(
            "<img src='%s' alt='error'> Grade: %s (%s/100)" % (img, letter, score)
        )

    @property
    def content(self):
        """
        Content of the panel when it's displayed in full screen.

        By default this renders the template defined by :attr:`template`.
        Statistics stored with :meth:`record_stats` are available in the
        template's context.
        """
        template = self.get_template()
        context = {"components": self.components}
        content = template.render(context)
        return content

    @lru_cache()
    def get_template(self):
        template_filename = pkg_resources.resource_filename("djt_csp", self.template)
        with open(template_filename) as fd:
            template_content = fd.read()
        template = template_from_string(template_content)
        return template
