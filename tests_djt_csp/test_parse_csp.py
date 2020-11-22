from djt_csp.csp_analyzis import CSPParser
from tests_djt_csp import BaseTestCase


class TestCSPParser(BaseTestCase):
    def test_cspparser_1(self):
        parser = CSPParser()
        policies = parser.get_csp_parser("default-src ftps: https:")
        self.assertEqual({"default-src": {"https:"}}, policies)

    def test_cspparser_2(self):
        parser = CSPParser()
        policies = parser.get_csp_parser(
            "default-src 'self'; img-src 'self' https://i.imgur.com; object-src 'none'"
        )
        self.assertEqual(
            {
                "default-src": {"self"},
                "img-src": {"self", "https://"},
                "object-src": {"none"},
            },
            policies,
        )

    def test_cspparser_3(self):
        parser = CSPParser()
        policies = parser.get_csp_parser(
            "default-src 'none'; font-src https://fonts.gstatic.com; "
            "img-src 'self' https://i.imgur.com; object-src 'none'; "
            "script-src 'self'; style-src 'self'"
        )
        self.assertEqual(
            {
                "default-src": {"none"},
                "font-src": {"https://"},
                "img-src": {"self", "https://"},
                "object-src": {"none"},
                "script-src": {"self"},
                "style-src": {"self"},
            },
            policies,
        )

    def test_cspparser_4(self):
        parser = CSPParser()
        policies = parser.get_csp_parser(
            "default-src https: 'unsafe-eval' 'unsafe-inline'; object-src 'none'"
        )
        self.assertEqual(
            {
                "default-src": {"unsafe-eval", "https:", "unsafe-inline"},
                "object-src": {"none"},
            },
            policies,
        )

    def test_cspparser_5(self):
        parser = CSPParser()
        policies = parser.get_csp_parser("default-src 'none'; frame-ancestors 'none'")
        self.assertEqual(
            {"default-src": {"none"}, "frame-ancestors": {"none"}}, policies
        )

    def test_cspparser_6(self):
        parser = CSPParser(
            "default-src 'none' ; script-src 'self' ; font-src 'self' ; style-src 'self' 'unsafe-inline' ; img-src 'self' data: ; object-src 'none'; frame-ancestors 'none'; frame-src 'none'; connect-src *; "
        )
        parser.load()
        return parser.policies
