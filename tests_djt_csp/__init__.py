import os
from unittest import TestCase

import django

os.environ["DJANGO_SETTINGS_MODULE"] = "tests_djt_csp.settings"
django.setup()


class BaseTestCase(TestCase):
    pass
