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
import re
from html import escape
from logging import INFO, ERROR, WARNING
from typing import Optional, Tuple, Dict, List, Union

from django.conf import settings
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _

from djt_csp.csp_analyzis import get_csp_analyzis, bool_icon, get_csp_parser

CHECKED_HTTP_HEADERS = {
    "content-security-policy",
    "access-control-allow-origin",
    "strict-transport-security",
    "public-key-pins",
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


class Checker:
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
        self.cookies = stats["cookies"]  # type: List[Dict[str, Union[str, bool]]]
        self.is_secure = stats["is_secure"]  # type: bool

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


class HeaderChecker(Checker):
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


class ContentTypeSniff(HeaderChecker):
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


class RefererComponent(HeaderChecker):
    """
    referrer-policy-private	Referrer-Policy header set to no-referrer or same-origin, strict-origin or
        strict-origin-when-cross-origin	5
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


class XSSProtection(HeaderChecker):
    """
x-xss-protection-not-needed-due-to-csp	X-XSS-Protection header not needed due to strong
        Content Security Policy (CSP) header	0
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


class FrameOptions(HeaderChecker):
    """x-frame-options-implemented-via-csp	X-Frame-Options (XFO) implemented via the CSP frame-ancestors directive	5
x-frame-options-allow-from-origin	X-Frame-Options (XFO) header uses ALLOW-FROM uri directive	0
x-frame-options-sameorigin-or-deny	X-Frame-Options (XFO) header set to SAMEORIGIN or DENY	0
x-frame-options-not-implemented	X-Frame-Options (XFO) header not implemented	-20
x-frame-options-header-invalid	X-Frame-Options (XFO) header cannot be recognized	-20
"""

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

    @property
    def content(self) -> str:
        value, src = self.get_header("Content-Security-Policy")
        parser = get_csp_parser(value, is_secure=self.is_secure)
        if parser and "frame-ancestors" in parser.by_directive:
            content = "<p>%s</p>" % _(
                "X-Frame-Options (XFO) implemented via the CSP frame-ancestors directive."
            )
        else:
            content = super().content
        return mark_safe(content)

    @property
    def score(self) -> int:
        value, src = self.get_header("Content-Security-Policy")
        parser = get_csp_parser(value, is_secure=self.is_secure)
        if parser and parser.sources("frame-ancestors").isdisjoint({"http:", "https:"}):
            return 5
        return super().score


class ScriptIntegrityChecker(Checker):
    """
sri-implemented-and-all-scripts-loaded-securely	                Subresource Integrity (SRI) is implemented 
        and all scripts are loaded from a similar origin	5
sri-implemented-and-external-scripts-loaded-securely	        Subresource Integrity (SRI) is implemented
        and all scripts are loaded securely	5
sri-not-implemented-but-all-scripts-loaded-from-secure-origin	Subresource Integrity (SRI) not implemented 
        as all scripts are loaded from a similar origin	0

sri-not-implemented-but-external-scripts-loaded-securely	    Subresource Integrity (SRI) not implemented, 
        but all external scripts are loaded over https	-5
sri-implemented-but-external-scripts-not-loaded-securely	    Subresource Integrity (SRI) implemented, but 
        external scripts are loaded over http	-20
sri-not-implemented-and-external-scripts-not-loaded-securely	Subresource Integrity (SRI) is not implemented,
        and external scripts are not loaded over https	-50
sri-not-implemented-but-no-scripts-loaded	                    Subresource Integrity (SRI) is not needed since
        site contains no script tags	0
sri-not-implemented-response-not-html	                        Subresource Integrity (SRI) is only needed
        for html resources	0
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
            fmt_char = {"src": escape(src)}
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
                    "Subresource Integrity (SRI) not implemented but all scripts are loaded from a similar origin"
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


class CORSChecker(HeaderChecker):
    """cross-origin-resource-sharing-
implemented-with-public-access	Public content is visible via cross-origin resource sharing (CORS)
        Access-Control-Allow-Origin header	0
cross-origin-resource-sharing-implemented-with-restricted-access	Content is visible via cross-origin 
        resource sharing (CORS) files or headers, but is restricted to specific domains	0
cross-origin-resource-sharing-not-implemented	Content is not visible via cross-origin resource sharing
        (CORS) files or headers	0
xml-not-parsable	crossdomain.xml or clientaccesspolicy.xml claims to be xml, but cannot be parsed	-20
cross-origin-resource-sharing-implemented-with-universal-access"""

    header_name = "Access-Control-Allow-Origin"
    reference_link = "https://infosec.mozilla.org/guidelines/web_security#cross-origin-resource-sharing"

    @property
    def content(self) -> str:
        value, src = self.get_header(self.header_name)
        if value is None:
            return _(
                "The %(h)s HTTP header is intended for API endpoints and resources."
            ) % {"h": self.header_name}
        return _('Header %(h)sis set to "%(v)s"') % {
            "v": escape(value),
            "h": self.header_name,
        }

    def is_valid(self, value):
        return value in self.header_values

    @property
    def score(self) -> int:
        return 0


class HSTSChecker(HeaderChecker):
    """
hsts-preloaded	Preloaded via the HTTP Strict Transport Security (HSTS) preloading process	5
hsts-implemented-max-age-at-least-six-months	HTTP Strict Transport Security (HSTS) header set 
    to a minimum of six months (15768000)	0
hsts-implemented-max-age-less-than-six-months	HTTP Strict Transport Security (HSTS) header set 
    to less than six months (15768000)	-10

hsts-not-implemented	HTTP Strict Transport Security (HSTS) header not implemented	-20
hsts-header-invalid	HTTP Strict Transport Security (HSTS) header cannot be recognized	-20
hsts-not-implemented-no-https	HTTP Strict Transport Security (HSTS) header cannot be
    set for sites not available over https	-20
hsts-invalid-cert	HTTP Strict Transport Security (HSTS) header cannot be set, as site 
    contains an invalid certificate chain	-20
"""

    header_name = "Strict-Transport-Security"
    reference_link = "https://infosec.mozilla.org/guidelines/web_security#http-strict-transport-security"
    invalid_score = -20
    missing_score = -20

    def __init__(self, stats):
        super().__init__(stats)
        self.age = 0
        self.preload = False
        self.subdomains = False
        self.invalid = False

    @property
    def content(self) -> str:
        content, __ = self.analyzis
        return mark_safe(content)

    @property
    def score(self) -> int:
        __, score = self.analyzis
        return score

    @property
    def level(self) -> int:
        __, score = self.analyzis
        if score < 0 and self.is_secure:
            return WARNING
        return INFO

    @cached_property
    def analyzis(self) -> Tuple[str, int]:
        name = self.header_name
        value, src = self.get_header(name)
        fmt = {"h": name, "v": escape(value or "")}
        if value is None and not self.is_secure:
            msg = _(
                "The %(h)s HTTP header cannot be set for sites not available over https."
            )
            return msg % fmt, self.missing_score
        elif value is None:
            msg = _("The %(h)s HTTP header not implemented.")
            return msg % fmt, self.missing_score
        components = {x.strip() for x in value.split(";")}
        while components:
            sub_value = components.pop()
            self.check_component(sub_value)
        fmt.update(
            {"age": self.age, "preload": self.preload, "subdomains": self.subdomains}
        )
        if self.invalid or self.age == 0:
            msg = "The %(h)s HTTP header cannot be parsed ('%(v)s' is invalid)."
            return msg % fmt, self.invalid_score
        return self.get_message(fmt)

    def get_message(self, fmt):
        if self.age <= 15768000:
            msg = _(
                "The %(h)s HTTP header set to less than six months (%(age)s <= 15768000)"
            )
            score = -10
        elif self.preload:
            msg = _("Preloaded via the HTTP %(h)s preloading process")
            score = 5
        else:
            msg = _("The %(h)s HTTP header set to a minimum of six months (15768000)")
            score = 0
        return msg % fmt, score

    def check_component(self, sub_value):
        matcher = re.match(r"^max-age=([1-9]\d*)$", sub_value)
        if matcher:
            self.age = int(matcher.group(1))
        elif re.match('^report-uri="http.*"$', sub_value):
            return
        elif sub_value == "preload":
            self.preload = True
        elif sub_value == "includeSubDomains":
            self.subdomains = True
        else:
            self.invalid = True


class HPKPChecker(HSTSChecker):
    """
hpkp-preloaded	Preloaded via the HTTP Public Key Pinning (HPKP) preloading process	0
hpkp-implemented-max-age-at-least-fifteen-days	HTTP Public Key Pinning (HPKP) header
    set to a minimum of 15 days (1296000)	0
hpkp-implemented-max-age-less-than-fifteen-days	HTTP Public Key Pinning (HPKP) header
    set to less than 15 days (1296000)	0
hpkp-not-implemented	HTTP Public Key Pinning (HPKP) header not implemented	0
hpkp-invalid-cert	HTTP Public Key Pinning (HPKP) header cannot be set,
    as site contains an invalid certificate chain	0
hpkp-not-implemented-no-https	HTTP Public Key Pinning (HPKP) header can't be implemented without https	0
hpkp-header-invalid	HTTP Public Key Pinning (HPKP) header cannot be recognized	-5
"""

    header_name = "Public-Key-Pins"
    reference_link = (
        "https://infosec.mozilla.org/guidelines/web_security#http-public-key-pinning"
    )
    invalid_score = -5
    missing_score = 0

    def __init__(self, stats):
        super().__init__(stats)
        self.pinned_keys = set()

    def get_message(self, fmt):
        score = 0
        if len(self.pinned_keys) == 0:
            msg = _("No public key is defined by the %(h)s HTTP header.")
            score = -5
        elif self.age <= 1296000:
            msg = _(
                "The %(h)s HTTP header set to less than 15 days (%(age)s <= 1296000)"
            )
        elif self.preload:
            msg = _("Preloaded via the HTTP %(h)s preloading process")
        else:
            msg = _("The %(h)s HTTP header set to a minimum of 15 days (1296000)")
        return msg % fmt, score

    def check_component(self, sub_value):
        matcher = re.match(r"^pin-(sha256-[A-Za-z\d+/]+)$", sub_value)
        if matcher:
            self.pinned_keys.add(matcher.group(1))
        else:
            super().check_component(sub_value)


class CookieAnalyzer(Checker):
    """
cookies-secure-with-httponly-sessions-and-samesite	All cookies use the Secure flag, session cookies use the 
        HttpOnly flag, and cross-origin restrictions are in place via the SameSite flag	5
cookies-not-found	No cookies detected	0
cookies-secure-with-httponly-sessions	All cookies use the Secure flag and all session cookies use the HttpOnly 
        flag	0
cookies-without-secure-flag-but-protected-by-hsts	Cookies set without using the Secure flag, but transmission 
        over HTTP prevented by HSTS	-5
cookies-session-without-secure-flag-but-protected-by-hsts	Session cookie set without the Secure flag, but 
        transmission over HTTP prevented by HSTS	-10
cookies-without-secure-flag	Cookies set without using the Secure flag or set over http	-20
cookies-samesite-flag-invalid	Cookies use SameSite flag, but set to something other than Strict or Lax	-20
cookies-anticsrf-without-samesite-flag	Anti-CSRF tokens set without using the SameSite flag	-20
cookies-session-without-httponly-flag	Session cookie set without using the HttpOnly flag	-30
cookies-session-without-secure-flag	Session cookie set without using the Secure flag or set over http	-40
    """

    title = _("Cookies analyzis")
    reference_link = "https://infosec.mozilla.org/guidelines/web_security#cookies"

    @property
    def content(self) -> str:
        content, __ = self.analyzis
        return mark_safe(content)

    @property
    def score(self) -> int:
        __, score = self.analyzis
        return score

    @cached_property
    def analyzis(self) -> Tuple[str, int]:
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
                _("prefixed"),
            )
        )
        non_secure_count = 0
        no_cross_origin_count = 0
        non_prefixed_count = 0
        session_is_httponly = True
        csrf_is_samesite = True
        session_is_secure = True
        for cookie in self.cookies:
            name = cookie["name"]
            samesite_value = (cookie["samesite"] or "").lower()
            if name == settings.SESSION_COOKIE_NAME:
                session_is_httponly = session_is_httponly and cookie["httponly"]
                session_is_secure = session_is_secure and cookie["secure"]
            if name == settings.CSRF_COOKIE_NAME:
                csrf_is_samesite = csrf_is_samesite and (
                    samesite_value in {"strict", "lax"}
                )
            prefixed = name.startswith("__Secure-") or name.startswith("__Host-")
            if not prefixed:
                non_prefixed_count += 1
            if not cookie["secure"]:
                non_secure_count += 1
            if samesite_value not in {"strict", "lax"}:
                no_cross_origin_count += 1
            content += (
                "<tr>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "</tr>"
                % (
                    escape(name),
                    escape(cookie["path"]),
                    escape(cookie["domain"]),
                    bool_icon(cookie["secure"]),
                    escape(cookie["samesite"]),
                    bool_icon(cookie["httponly"]),
                    bool_icon(prefixed),
                )
            )
        content += "</tbody></table>\n"
        hsts, __ = self.get_header("Strict-Transport-Security")
        score = 0
        comment = ""
        if non_secure_count == 0 and session_is_httponly and no_cross_origin_count == 0:
            score = 5
        elif len(self.cookies) == 0:
            content = _("No cookies detected")
            score = 0
        elif non_secure_count == 0 and session_is_httponly:
            score = 0
            comment = _(
                "All cookies use the Secure flag and all session cookies use the HttpOnly flag"
            )
        elif hsts and non_secure_count > 0 and session_is_secure:
            comment = _(
                "Cookies set without using the Secure flag, but transmission over HTTP prevented by HSTS"
            )
            score = -5
        elif hsts and not session_is_secure:
            comment = _(
                "Session cookie set without the Secure flag, but transmission over HTTP prevented by HSTS"
            )
            score = -10
        if not csrf_is_samesite:
            comment = _("Anti-CSRF tokens set without using the SameSite flag")
            score = -20
        elif no_cross_origin_count > 0:
            comment = _(
                "Cookies use SameSite flag, but set to something other than Strict or Lax"
            )
            score = -20
        if not session_is_httponly:
            comment = _("Session cookie set without using the HttpOnly flag")
            score = -30
        if not session_is_secure:
            comment = _(
                "Session cookie set without using the Secure flag or set over http"
            )
            score = -40
        if comment:
            content = "<p>%s.</p>%s" % (comment, content)
        return content, score


class CSPChecker(HeaderChecker):
    """

csp-implemented-with-no-unsafe-default-src-none	Content Security Policy (CSP) implemented with
    default-src 'none' and without 'unsafe-inline' or 'unsafe-eval'	10
csp-implemented-with-no-unsafe	Content Security Policy (CSP) implemented without 'unsafe-inline' or 'unsafe-eval'	5
csp-implemented-with-unsafe-inline-in-style-src-only	Content Security Policy (CSP) implemented with unsafe
    directives inside style-src. This includes 'unsafe-inline', data:, or overly broad sources such as https:.	0
csp-implemented-with-insecure-scheme-in-passive-content-only	Content Security Policy (CSP) implemented, but
    secure site allows images or media to be loaded over http	-10
csp-implemented-with-unsafe-eval	Content Security Policy (CSP) implemented, but allows 'unsafe-eval'	-10
csp-implemented-with-insecure-scheme	Content Security Policy (CSP) implemented, but secure site allows resources
    to be loaded from http	-20
csp-implemented-with-unsafe-inline	Content Security Policy (CSP) implemented unsafely. This includes
    \'unsafe-inline\' or data: inside script-src, overly broad sources such as https: inside object-src or script-src,
    or not restricting the sources for object-src or script-src.	-20
csp-header-invalid	Content Security Policy (CSP) header cannot be parsed successfully	-25
csp-not-implemented	Content Security Policy (CSP) header not implemented	-25
"""

    reference_link = (
        "https://infosec.mozilla.org/guidelines/web_security#content-security-policy"
    )
    header_name = "Content-Security-Policy"

    @property
    def content(self,) -> str:
        value, src = self.get_header(self.header_name)
        content, __ = get_csp_analyzis(
            value, is_secure=self.is_secure or settings.DEBUG
        )
        return mark_safe(content)

    @property
    def score(self) -> int:
        value, src = self.get_header(self.header_name)
        __, score = get_csp_analyzis(value, is_secure=self.is_secure or settings.DEBUG)
        return score

    @property
    def level(self) -> int:
        value, src = self.get_header(self.header_name)
        if value is None:
            return WARNING
        return INFO
