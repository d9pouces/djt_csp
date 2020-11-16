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
import json
from functools import lru_cache
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import pkg_resources
import requests
from debug_toolbar.panels import Panel
from django.conf import settings
from django.http import HttpResponse, HttpRequest
# noinspection PyProtectedMember
from django.template import engines, TemplateSyntaxError
from django.templatetags.static import static
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe


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


class CSPPanel(Panel):
    """based on https://github.com/peterbe/django-html-validator

and https://github.com/validator/validator/wiki/Output-»-JSON

     """

    name = "Security Headers"
    title = "Security headers"
    template = "templates/debug/validator.html"
    has_content = True

    @cached_property
    def base_url(self):
        if hasattr(settings, "DJT_NVU_URL"):
            return settings.DJT_NVU_URL
        return "https://html5.validator.nu/"

    def generate_stats(self, request: HttpRequest, response: HttpResponse):
        content_type = response["Content-Type"]
        if not content_type.startswith("text/html"):
            return
        if response.status_code < 200 or (300 <= response.status_code < 400):
            return
        content_text = response.content
        nu_messages = self.validate(content_text, content_type=content_type)
        for m in nu_messages["messages"]:
            if "extract" in m:
                m["extract"] = m["extract"].strip()
        values = {
            "content_text": content_text,
            "content_type": content_type,
            "nu_messages": nu_messages,
        }
        self.record_stats(values)

    def nav_subtitle(self):
        stats = self.get_stats()
        nu_messages = stats.get("nu_messages", {})
        messages = nu_messages.get("messages", [])

        if any(x["type"] == "unable" for x in messages):
            return mark_safe(
                "<img src='%s' alt='error'> Unable to validate HTML"
                % (static("admin/img/icon-no.svg"))
            )
        elif any(x["type"] == "error" for x in messages):
            return mark_safe(
                "<img src='%s' alt='error'> Invalid HTML (%d messages)"
                % (static("admin/img/icon-no.svg"), len(messages))
            )
        return mark_safe(
            "<img src='%s' alt='error'> Valid HTML! (%d messages)"
            % (static("admin/img/icon-yes.svg"), len(messages))
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
        context = self.get_stats()
        content = template.render(context)
        return content

    @lru_cache()
    def get_template(self):
        template_filename = pkg_resources.resource_filename("djt_csp", self.template)
        with open(template_filename) as fd:
            template_content = fd.read()
        template = template_from_string(template_content)
        return template

    def validate(self, content, content_type="text/html"):
        parsed_url = urlparse(self.base_url)
        query = parse_qs(parsed_url.query)
        query["out"] = ["json"]
        url = urlunparse(
            (*parsed_url[:4], urlencode(query, doseq=True), parsed_url[-1])
        )
        try:
            r = requests.post(
                url, data=content, headers={"Content-Type": content_type}, timeout=1,
            )
            if r.status_code == 200:
                return json.loads(r.text)
            message = "Invalid response from %s (%s)" % (self.base_url, r.status_code)
        except requests.ConnectionError as e:
            message = "Unable to contact %s (%s)" % (self.base_url, e)
        except Exception as e:
            message = "Unknown error when connecting to %s (%s)" % (self.base_url, e)
        return {"messages": [{"type": "unable", "message": message}]}
