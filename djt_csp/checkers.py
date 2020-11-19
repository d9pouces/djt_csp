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
"""
https://github.com/mozilla/http-observatory/blob/master/httpobs/docs/scoring.md

"""
import html
from html import escape
from logging import INFO, ERROR, WARNING
from typing import Optional, Tuple, Dict, List

from django.utils.functional import cached_property
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

CHECKED_HTTP_HEADERS = {
    "content-security-policy",
    "content-security-policy-report-only",
    "access-control-allow-origin",
    "strict-transport-security",
    "referrer-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
}
CHECKED_RESOURCES = {
    "script": "src",
    "img": "src",
    "audio": "src",
    "video": "src",
    "link": "href",
    "iframe": "src",
}


class Component:
    title = None
    description = None
    reference_link = None

    def __init__(self, stats):
        self.html_headers = stats["html_headers"]  # type: Dict[str, str]
        self.response_headers = stats["response_headers"]  # type: Dict[str, str]
        self.content_type = stats["content_type"]  # str
        self.scripts_attributes = stats[
            "scripts_attributes"
        ]  # type: List[Dict[str, str]]
        self.http_ws_resources = stats[
            "http_ws_resources"
        ]  # type: Dict[str, List[str]]
        self.cookies = stats["cookies"]  # type: List[Dict[str, str]]

    def load(self):
        pass

    @property
    def level(self) -> int:
        """return one of logging.{INFO, WARNING, ERROR, FATAL}"""
        return INFO

    @property
    def icon(self) -> str:
        if self.level >= ERROR:
            return "admin/img/icon-no.svg"
        elif self.level >= WARNING or self.score < 0:
            return "admin/img/icon-alert.svg"
        return "admin/img/icon-yes.svg"

    @property
    def content(self) -> str:
        raise NotImplementedError

    @property
    def score(self) -> int:
        raise NotImplementedError

    def get_header(self, header_name: str) -> Tuple[Optional[str], bool]:
        header_name_low = header_name.lower()
        if header_name_low in self.response_headers:
            return self.response_headers[header_name_low], True
        if header_name_low in self.html_headers:
            return self.html_headers[header_name_low], False
        return None, False


class HeaderComponent(Component):

    header_name = None  # type: str
    header_values = {
        None: 0,
    }  # type: Dict[Optional[str], int]
    invalid_valid_score = 0

    @property
    def title(self):
        value, src = self.get_header(self.header_name)
        if value is None:
            return _("%(h)s HTTP header (not set)") % {"h": self.header_name}
        elif src:
            return _("%(h)s HTTP header") % {"h": self.header_name}
        return _("%(h)s HTTP header (set through a HTML meta tag)") % {
            "h": self.header_name
        }

    @property
    def content(self) -> str:
        value, src = self.get_header(self.header_name)
        if value is None:
            return _("You should use the %(h)s HTTP header.") % {"h": self.header_name}
        elif self.is_valid(value):
            if self.header_values[value] < self.best_value:
                return _('Header is set to "%(v)s".') % {
                    "v": value,
                }
            return _('Header is set to "%(v)s", that is a best choice.') % {
                "v": value,
            }
        return _('Header is set to "%(v)s", which is invalid.') % {"v": value}

    def is_valid(self, value):
        return value in self.header_values

    @property
    def score(self) -> int:
        value, src = self.get_header(self.header_name)
        return self.header_values.get(value, self.invalid_valid_score)

    @property
    def level(self) -> int:
        value, src = self.get_header(self.header_name)
        if value is not None and value not in self.header_values:
            return WARNING
        return INFO

    @cached_property
    def best_value(self):
        return max(self.header_values.values())


class ContentTypeSniff(HeaderComponent):
    """x-content-type-options-nosniff	X-Content-Type-Options header set to nosniff	0
x-content-type-options-not-implemented	X-Content-Type-Options header not implemented	-5
x-content-type-options-header-invalid	X-Content-Type-Options header cannot be recognized	-5
"""

    header_name = "X-Content-Type-Options"
    reference_link = (
        "https://infosec.mozilla.org/guidelines/web_security#x-content-type-options"
    )
    header_values = {None: -5, "nosniff": 0}
    invalid_valid_score = -5


class RefererComponent(HeaderComponent):
    """referrer-policy-private	Referrer-Policy header set to no-referrer or same-origin, strict-origin or strict-origin-when-cross-origin	5
referrer-policy-no-referrer-when-downgrade	Referrer-Policy header set to no-referrer-when-downgrade	0
referrer-policy-not-implemented	Referrer-Policy header not implemented	0
referrer-policy-unsafe	Referrer-Policy header unsafely set to origin, origin-when-cross-origin, or unsafe-url	-5
referrer-policy-header-invalid	Referrer-Policy header cannot be recognized	-5
"""

    header_name = "Referrer-Policy"
    reference_link = (
        "https://infosec.mozilla.org/guidelines/web_security#referrer-policy"
    )
    invalid_valid_score = -5
    header_values = {
        "no-referrer": 5,
        "same-origin": 5,
        "strict-origin": 5,
        "strict-origin-when-cross-origin": 5,
        "no-referrer-when-downgrade": 0,
        None: 0,
        "": 0,
        "origin": -5,
        "origin-when-cross-origin": -5,
        "unsafe-url": -5,
    }


class XSSProtection(HeaderComponent):
    """x-xss-protection-not-needed-due-to-csp	X-XSS-Protection header not needed due to strong Content Security Policy (CSP) header	0
x-xss-protection-enabled-mode-block	X-XSS-Protection header set to 1; mode=block	0
x-xss-protection-enabled	X-XSS-Protection header set to 1	0
x-xss-protection-disabled	X-XSS-Protection header set to 0 (disabled)	-10
x-xss-protection-not-implemented	X-XSS-Protection header not implemented	-10
x-xss-protection-header-invalid	X-XSS-Protection header cannot be recognized	-10
"""

    # TODO: use x-xss-protection-not-needed-due-to-csp
    reference_link = (
        "https://infosec.mozilla.org/guidelines/web_security#x-xss-protection"
    )
    invalid_valid_score = -10
    header_name = "X-XSS-Protection"
    header_values = {
        "1; mode=block": 0,
        "1": 0,
        "0": -10,
        None: -10,
    }


class FrameOptions(HeaderComponent):
    """x-frame-options-implemented-via-csp	X-Frame-Options (XFO) implemented via the CSP frame-ancestors directive	5
x-frame-options-allow-from-origin	X-Frame-Options (XFO) header uses ALLOW-FROM uri directive	0
x-frame-options-sameorigin-or-deny	X-Frame-Options (XFO) header set to SAMEORIGIN or DENY	0
x-frame-options-not-implemented	X-Frame-Options (XFO) header not implemented	-20
x-frame-options-header-invalid	X-Frame-Options (XFO) header cannot be recognized	-20
"""

    # TODO: use x-frame-options-implemented-via-csp
    reference_link = (
        "https://infosec.mozilla.org/guidelines/web_security#x-frame-options"
    )
    invalid_valid_score = -20
    header_name = "X-Frame-Options"
    header_values = {
        None: -20,
        "SAMEORIGIN": 0,
        "DENY": 0,
        "ALLOW-FROM": 0,
    }


class ScriptIntegrityCheck(Component):
    """
sri-implemented-and-all-scripts-loaded-securely	                Subresource Integrity (SRI) is implemented and all scripts are loaded from a similar origin	5
sri-implemented-and-external-scripts-loaded-securely	        Subresource Integrity (SRI) is implemented and all scripts are loaded securely	5
sri-not-implemented-but-all-scripts-loaded-from-secure-origin	Subresource Integrity (SRI) not implemented as all scripts are loaded from a similar origin	0

sri-not-implemented-but-external-scripts-loaded-securely	    Subresource Integrity (SRI) not implemented, but all external scripts are loaded over https	-5
sri-implemented-but-external-scripts-not-loaded-securely	    Subresource Integrity (SRI) implemented, but external scripts are loaded over http	-20
sri-not-implemented-and-external-scripts-not-loaded-securely	Subresource Integrity (SRI) is not implemented, and external scripts are not loaded over https	-50
sri-not-implemented-but-no-scripts-loaded	                    Subresource Integrity (SRI) is not needed since site contains no script tags	0
sri-not-implemented-response-not-html	                        Subresource Integrity (SRI) is only needed for html resources	0
"""

    title = _("Subresource Integrity")
    reference_link = (
        "https://infosec.mozilla.org/guidelines/web_security#subresource-integrity"
    )

    @property
    def content(self) -> str:
        __, notes = self.analyzed_data
        return mark_safe(
            "<ul>" + "\n".join(["<li>%s</li>" % x for x in notes]) + "</ul>"
        )

    @cached_property
    def analyzed_data(self):
        notes = []
        sri_counts = {"http": 0, "https": 0, "similar": 0}
        no_sri_counts = {"http": 0, "https": 0, "similar": 0}
        for attr in self.scripts_attributes:
            src = attr.get("src", "")
            fmt_char = {"src": html.escape(src)}
            if src.startswith("http://"):
                key = "http"
                notes.append(_("You should load %(src)s over https") % fmt_char)
            elif src.startswith("https://"):
                key = "https"
            else:
                key = "similar"
            if attr.get("crossorigin") != "anonymous" or not attr.get("integrity"):
                no_sri_counts[key] += 1
                notes.append(_("You should implement SRI to use %(src)s") % fmt_char)
            else:
                sri_counts[key] += 1
        if sum(sri_counts.values()) + sum(no_sri_counts.values()) == 0:
            note = 0
            notes.append(
                _(
                    "Subresource Integrity (SRI) is not needed since site contains no script tags"
                )
            )
        elif no_sri_counts["http"] > 0:
            note = -50
        elif sri_counts["http"] > 0:
            note = -20
        elif no_sri_counts["https"] > 0:
            note = -5
        elif no_sri_counts["similar"] > 0:
            note = 0
            notes.append(
                _(
                    "Subresource Integrity (SRI) not implemented as all scripts are loaded from a similar origin"
                )
            )
        elif sri_counts["similar"] + sri_counts["https"] > 0:
            note = 5
            notes.append(
                _(
                    "Subresource Integrity (SRI) is implemented and all scripts are loaded securely"
                )
            )
        else:
            note = 0
        return note, notes

    @property
    def score(self) -> int:
        note, __ = self.analyzed_data
        return note


class CORSComponent(HeaderComponent):
    """cross-origin-resource-sharing-
implemented-with-public-access	Public content is visible via cross-origin resource sharing (CORS) Access-Control-Allow-Origin header	0
cross-origin-resource-sharing-implemented-with-restricted-access	Content is visible via cross-origin resource sharing (CORS) files or headers, but is restricted to specific domains	0
cross-origin-resource-sharing-not-implemented	Content is not visible via cross-origin resource sharing (CORS) files or headers	0
xml-not-parsable	crossdomain.xml or clientaccesspolicy.xml claims to be xml, but cannot be parsed	-20
cross-origin-resource-sharing-implemented-with-universal-access"""

    header_name = "Referrer-Policy"
    reference_link = "https://infosec.mozilla.org/guidelines/web_security#cross-origin-resource-sharing"
    invalid_valid_score = -5
    header_values = {
        "no-referrer": 5,
        "same-origin": 5,
        "strict-origin": 5,
        "strict-origin-when-cross-origin": 5,
        "no-referrer-when-downgrade": 0,
        None: 0,
        "": 0,
        "origin": -5,
        "origin-when-cross-origin": -5,
        "unsafe-url": -5,
    }


class CookieAnalyzer(Component):
    """
cookies-secure-with-httponly-sessions-and-samesite	All cookies use the Secure flag, session cookies use the HttpOnly flag, and cross-origin restrictions are in place via the SameSite flag	5
cookies-not-found	No cookies detected	0
cookies-secure-with-httponly-sessions	All cookies use the Secure flag and all session cookies use the HttpOnly flag	0
cookies-without-secure-flag-but-protected-by-hsts	Cookies set without using the Secure flag, but transmission over HTTP prevented by HSTS	-5
cookies-session-without-secure-flag-but-protected-by-hsts	Session cookie set without the Secure flag, but transmission over HTTP prevented by HSTS	-10
cookies-without-secure-flag	Cookies set without using the Secure flag or set over http	-20
cookies-samesite-flag-invalid	Cookies use SameSite flag, but set to something other than Strict or Lax	-20
cookies-anticsrf-without-samesite-flag	Anti-CSRF tokens set without using the SameSite flag	-20
cookies-session-without-httponly-flag	Session cookie set without using the HttpOnly flag	-30
cookies-session-without-secure-flag	Session cookie set without using the Secure flag or set over http	-40
    """

    reference_link = "https://infosec.mozilla.org/guidelines/web_security#cookies"

    def content(self) -> str:
        content = (
            "<table><thead><tr>"
            "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
            "</tr></thead><tbody>\n"
            % (
                _("name"),
                _("path"),
                _("domain"),
                _("secure"),
                _("samesite"),
                _("HTTP only"),
                _("max age"),
            )
        )

        for cookie in self.cookies:
            content += "<tr><td>%s</td>" \
                       "<td>%s</td>" \
                       "</tr>" % (escape(cookie["name"]), escape(cookie["path"]))


        content += "</tbody></table>"
        pass
        [
            {
                "name": "s_1",
                "expires": "Fri, 19-Nov-2021 07:09:37 GMT",
                "path": "/",
                "comment": "",
                "domain": "",
                "max-age": 31536000,
                "secure": True,
                "version": "",
                "httponly": True,
                "samesite": "Strict",
            },
            {
                "name": "s_2",
                "expires": "Fri, 19-Nov-2021 07:09:37 GMT",
                "path": "/",
                "comment": "",
                "domain": "",
                "max-age": 31536000,
                "secure": True,
                "version": "",
                "httponly": "",
                "samesite": "None",
            },
            {
                "name": "s_3",
                "expires": "Fri, 19-Nov-2021 07:09:37 GMT",
                "path": "/",
                "comment": "",
                "domain": "",
                "max-age": 31536000,
                "secure": "",
                "version": "",
                "httponly": True,
                "samesite": "Lax",
            },
        ]


class CSPComponent(Component):
    """csp-implemented-with-no-unsafe-default-src-none	Content Security Policy (CSP) implemented with default-src 'none' and without 'unsafe-inline' or 'unsafe-eval'	10
csp-implemented-with-no-unsafe	Content Security Policy (CSP) implemented without 'unsafe-inline' or 'unsafe-eval'	5
csp-implemented-with-unsafe-inline-in-style-src-only	Content Security Policy (CSP) implemented with unsafe directives inside style-src. This includes 'unsafe-inline', data:, or overly broad sources such as https:.	0
csp-implemented-with-insecure-scheme-in-passive-content-only	Content Security Policy (CSP) implemented, but secure site allows images or media to be loaded over http	-10
csp-implemented-with-unsafe-eval	Content Security Policy (CSP) implemented, but allows 'unsafe-eval'	-10
csp-implemented-with-insecure-scheme	Content Security Policy (CSP) implemented, but secure site allows resources to be loaded from http	-20
csp-implemented-with-unsafe-inline	Content Security Policy (CSP) implemented unsafely. This includes \'unsafe-inline\' or data: inside script-src, overly broad sources such as https: inside object-src or script-src, or not restricting the sources for object-src or script-src.	-20
csp-not-implemented	Content Security Policy (CSP) header not implemented	-25
csp-header-invalid	Content Security Policy (CSP) header cannot be parsed successfully	-25
"""
