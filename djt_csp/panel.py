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
from functools import cached_property, lru_cache
from logging import CRITICAL, ERROR, INFO, WARNING
from typing import List

import pkg_resources
from debug_toolbar.panels import Panel
from django.http import HttpRequest, HttpResponse
# noinspection PyProtectedMember
from django.template import TemplateSyntaxError, engines
from django.templatetags.static import static
from django.utils.safestring import mark_safe

from djt_csp.checkers import (
    CORSChecker,
    CSPChecker,
    Checker,
    ContentTypeSniff,
    CookieAnalyzer,
    FrameOptions,
    HPKPChecker,
    HSTSChecker,
    RefererComponent,
    ScriptIntegrityChecker,
    XSSProtection,
)
from djt_csp.page_data import get_response_characteristics


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


class SecurityPanel(Panel):
    """
    """

    name = "Security score"
    title = "Security score"
    template = "templates/debug/security_panel.html"
    has_content = True

    def generate_stats(self, request: HttpRequest, response: HttpResponse):
        characteristics = get_response_characteristics(request, response)
        if characteristics is not None:
            self.record_stats(characteristics)

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
