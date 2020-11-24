import re
from functools import lru_cache
from typing import Optional, Set, Dict, Tuple

from django.templatetags.static import static
from django.utils.translation import gettext as _


def bool_icon(b: bool) -> str:
    icon = "admin/img/icon-no.svg"
    if b:
        icon = "admin/img/icon-yes.svg"
    return '<img src="%s" alt="%s">' % (static(icon), b)


class CSPParser:
    fetch_directives = {
        "child-src",
        "connect-src",
        "default-src",
        "font-src",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "object-src",
        "prefetch-src",
        "script-src",
        "script-src-elem",
        "script-src-attr",
        "style-src",
        "style-src-elem",
        "style-src-attr",
        "worker-src",
    }
    document_directives = {"base-uri", "plugin-types", "sandbox"}
    navigation_directives = {"form-action", "frame-ancestors", "navigate-to"}
    report_directives = {"report-uri", "report-to"}
    other_directives = {
        "block-all-mixed-content",
        "referrer",
        "require-sri-for",
        "trusted-types",
        "upgrade-insecure-requests",
    }
    all_directives = (
        fetch_directives
        | document_directives
        | navigation_directives
        | report_directives
        | other_directives
    )
    any_sources = {
        "http:",
        "https:",
        "blob:",
        "mediastream:",
        "filesystem:",
        "data:",
        "unsafe-eval",
        "unsafe-hashes",
        "unsafe-inline",
    }

    fetch_source_re = re.compile(
        r"^("
        r"'http:'|'https:'|'ftp:'|'ftps:'|'blob:'|'mediastream:'|'filesystem:'|'data:'|"
        r"http:|https:|ftp:|ftps:|blob:|mediastream:|filesystem:|data:|"
        r"'self'|'unsafe-eval'|'unsafe-hashes'|'unsafe-inline'|'report-sample'|"
        r"'strict-dynamic'|'none'|'nonce-[A-Za-z\d+/]+'|"
        r"'sha256-[A-Za-z\d+/]+'|'sha384-[A-Za-z\d+/]+'|'sha512-[A-Za-z\d+/]+'|"
        r"(http://|https://|ftp://|ftps://)?[\w*\-]+\.[\w.\-]+(:\d{1,5})?"
        r")$"
    )
    navigation_source_re = fetch_source_re
    host_re = re.compile(r"^((http://|https://|ftp://|ftps://)?[\w.\-]+(:\d{1,5})?)$")
    data_re = re.compile(r"^(nonce-|sha256-|sha384-|sha512-)")

    def __init__(self, policies: str, is_secure: bool = True):
        self.policies = policies
        self.is_secure = is_secure
        self.by_directive = {}  # type: Dict[str, Set[str]]

    def load(self):
        if self.policies is None:
            return
        for policy in self.policies.split(";"):
            stripped = policy.strip()
            if not stripped:
                continue
            parsed_policy = self.parse_policy(stripped)
            if parsed_policy:
                directive, sources = parsed_policy
                self.by_directive[directive] = sources

    def parse_policy(self, policy: str) -> Optional[Tuple[str, Set[str]]]:
        directive, sep, arg = policy.partition(" ")
        if directive not in self.all_directives:
            raise ValueError("%s is not recognized" % directive)
        sources = set()
        if directive in self.fetch_directives:
            source_re = self.fetch_source_re
        elif directive in self.navigation_directives:
            source_re = self.navigation_source_re
        elif directive in {"base-uri"}:
            source_re = self.navigation_source_re
        else:
            return
        for source in arg.split(" "):
            if not source or not source_re.match(source):
                continue
            if self.host_re.match(source):
                if source.startswith("http://") or source.startswith("ftp://"):
                    sources.add("http://")
                elif source.startswith("https://") or source.startswith("ftps://"):
                    sources.add("https://")
                else:
                    sources |= {"http://", "https://"}
                continue
            source = source.replace("'", "")
            if self.data_re.match(source):
                sources.add(source.split("-")[0])
                continue
            sources.add(source)
        return directive, sources

    def sources(self, directive: str) -> Set[str]:
        if directive in self.fetch_directives:
            return self.by_directive.get(
                directive, self.by_directive.get("default-src", CSPParser.any_sources),
            )
        return self.by_directive.get(directive, CSPParser.any_sources)

    @property
    def check_unsafe_inline_script(self):
        """Blocks execution of inline JavaScript by not allowing 'unsafe-inline' inside script-src"""
        return "unsafe-inline" not in self.sources("script-src")

    @property
    def check_eval_script(self):
        """Blocks execution of JavaScript's eval() function by not allowing 'unsafe-eval' inside script-src"""
        return "unsafe-eval" not in self.sources("script-src")

    @property
    def check_object(self):
        """Blocks execution of plug-ins, using object-src restrictions"""
        return self.any_sources.isdisjoint(self.sources("object-src"))

    @property
    def check_unsafe_inline_style(self):
        """Blocks inline styles by not allowing 'unsafe-inline' inside style-src"""
        return "unsafe-inline" not in self.sources("style-src")

    @property
    def check_block_active_http_content(self):
        """Blocks loading of active content over HTTP or FTP"""
        active = (
            "connect-src",
            "frame-src",
            "object-src",
            "script-src",
            "script-src-elem",
            "script-src-attr",
            "worker-src",
        )
        return all({"http:"}.isdisjoint(self.sources(x)) for x in active)

    @property
    def check_block_passive_http_content(self):
        """Blocks loading of passive content over HTTP or FTP"""
        passive = (
            "child-src",
            "font-src",
            "img-src",
            "manifest-src",
            "media-src",
            "prefetch-src",
            "style-src",
            "style-src-elem",
            "style-src-attr",
        )
        return all({"http:"}.isdisjoint(self.sources(x)) for x in passive)

    @property
    def check_clickjacking_protection(self):
        """Clickjacking protection, using frame-ancestors"""
        return {"http:", "https:"}.isdisjoint(self.sources("frame-ancestors"))

    @property
    def check_default_deny(self):
        """Deny by default, using default-src 'none'"""
        return self.sources("default-src") == {"none"}

    @property
    def check_base_tag(self):
        """Restricts use of the &lt;base&gt; tag by using base-uri 'none', base-uri 'self', or specific origins"""
        base = self.sources("base-uri")
        return {"none", "self", "http://", "https://"}.issuperset(base)

    @property
    def check_form_destinations(self):
        """Restricts where &lt;form&gt; contents may be submitted by using form-action 'none',
        form-action 'self', or specific URIs"""
        base = self.sources("form-action")
        return {"none", "self", "http://", "https://"}.issuperset(base)

    @property
    def check_script_dynamic(self):
        """Uses CSP3's 'strict-dynamic' directive to allow dynamic script loading (optional)"""
        return "strict-dynamic" in self.sources("script-src")


@lru_cache()
def get_csp_parser(policies: str, is_secure: bool = True) -> Optional[CSPParser]:
    parser = CSPParser(policies, is_secure=is_secure)
    try:
        parser.load()
    except ValueError:
        return None
    return parser


@lru_cache()
def get_csp_analyzis(policies: Optional[str], is_secure: bool = True):
    if policies is None:
        return (
            "<p>%s</p>"
            % _(
                "Content Security Policy (CSP) header not implemented."
                " You should take a look at "
                '<a href="https://django-csp.readthedocs.io/en/latest/">Django CSP</a> to add it.'
            ),
            -25,
        )
    parser = get_csp_parser(policies, is_secure=is_secure)
    if parser is None:
        comment = _(
            "Content Security Policy (CSP) header cannot be parsed successfully."
        )
        score = -25
    elif parser.check_default_deny and all(
        {"unsafe-inline", "unsafe-eval"}.isdisjoint(parser.sources(x))
        for x in parser.fetch_directives
    ):
        comment = _(
            "Content Security Policy (CSP) implemented with default-src 'none'"
            " and without 'unsafe-inline' or 'unsafe-eval'"
        )
        score = 10
    elif all(
        {"unsafe-inline", "unsafe-eval"}.isdisjoint(parser.sources(x))
        for x in parser.fetch_directives
    ):
        comment = _(
            "Content Security Policy (CSP) implemented without 'unsafe-inline' or 'unsafe-eval'"
        )
        score = 5
    elif all(
        {"unsafe-inline", "data:", "http:", "https:"}.isdisjoint(parser.sources(x))
        for x in parser.fetch_directives
        if x != "style-src"
    ):
        comment = _(
            "Content Security Policy (CSP) implemented with unsafe directives inside style-src. "
            "This includes 'unsafe-inline', data:, or overly broad sources such as https: "
        )
        score = 0
    elif any(
        {"http:", "http://"}.intersection(parser.sources(x))
        for x in ("frame-src", "object-src", "media-src", "img-src",)
    ):
        comment = _(
            "Content Security Policy (CSP) implemented, but secure site allows images "
            "or media to be loaded over http"
        )
        score = -10
    elif any("unsafe-eval" in parser.sources(x) for x in parser.fetch_directives):
        comment = _(
            "Content Security Policy (CSP) implemented, but allows 'unsafe-eval'"
        )
        score = -10
    elif parser.is_secure and any(
        {"http://", "http:"}.intersection(parser.sources(x))
        for x in parser.fetch_directives
    ):
        comment = _(
            "Content Security Policy (CSP) implemented, but secure site allows resources to be loaded from http"
        )
        score = -20
    elif {"unsafe-inline", "data:", "https:"}.intersection(
        parser.sources("script-src")
    ) or {"https:"}.intersection(parser.sources("object-src")):
        comment = _(
            "Content Security Policy (CSP) implemented unsafely. This includes 'unsafe-inline' or data:"
            " inside script-src, overly broad sources such as https: inside object-src or script-src, or"
            " not restricting the sources for object-src or script-src."
        )
        score = -20
    elif not parser.is_secure:
        comment = _("Content Security Policy (CSP) implemented, but site is not secure")
        score = -10
    else:
        comment = None
        score = 0
    desc = ""
    if comment:
        desc += "<p>%s</p>\n" % comment
    if parser:
        desc += "<p>%s</p>" % _("HTTPS is assumed during this analyzis.")
        desc += "<table><thead>\n"
        desc += "<tr><th>%s</th><th>%s</th></tr>\n" % (_("Test"), _("Pass"))
        desc += "</thead><tbody>\n"
        for k in (
            "check_unsafe_inline_script",
            "check_eval_script",
            "check_object",
            "check_unsafe_inline_style",
            "check_block_active_http_content",
            "check_block_passive_http_content",
            "check_clickjacking_protection",
            "check_default_deny",
            "check_base_tag",
            "check_form_destinations",
            "check_script_dynamic",
        ):
            desc += "<tr><td>%s</td><td>%s</td></tr>\n" % (
                getattr(CSPParser, k).__doc__,
                bool_icon(getattr(parser, k)),
            )
        desc += "</tbody></table>\n"
    return desc, score
