"""Source-to-sink and safe-path checks for the Python taint pass."""

import unittest

from scanner.taint import analyze_taint


class TaintTests(unittest.TestCase):
    """Exercise direct sources, propagation, and non-tainted alternatives."""

    def assert_tainted(self, source: str, sink: str) -> None:
        """Assert a high-risk taint flow reaches the expected sink."""
        findings = analyze_taint(source, "python")
        self.assertTrue(any(sink in f.description and f.tainted for f in findings), findings)

    def assert_clean(self, source: str) -> None:
        """Assert a safe dataflow does not produce a taint finding."""
        self.assertEqual(analyze_taint(source, "python"), [])

    def test_request_to_eval(self) -> None:
        """Track Flask query input to eval."""
        self.assert_tainted("x = request.args.get('x')\neval(x)", "eval")

    def test_input_propagates_to_exec(self) -> None:
        """Track one alias assignment into exec."""
        self.assert_tainted("x = input()\ny = x\nexec(y)", "exec")

    def test_argv_to_shell(self) -> None:
        """Track command-line input to a shell sink."""
        self.assert_tainted("cmd = sys.argv[1]\nos.system(cmd)", "os.system")

    def test_environment_to_open(self) -> None:
        """Track environment-derived paths into open."""
        self.assert_tainted("path = os.environ.get('PATH_NAME')\nopen(path)", "open")

    def test_form_to_http(self) -> None:
        """Track form data into an outbound request."""
        self.assert_tainted("url = request.form['url']\nrequests.get(url)", "requests.get")

    def test_flask_request_attribute_to_sink(self) -> None:
        """Track a Flask request attribute through an alias."""
        self.assert_tainted("value = flask.request.args.get('value')\neval(value)", "eval")

    def test_django_request_to_file(self) -> None:
        """Track Django GET data into a file sink."""
        self.assert_tainted("name = request.GET.get('name')\nopen(name)", "open")

    def test_fastapi_request_annotation_to_sink(self) -> None:
        """Track a FastAPI Request parameter through query parameters."""
        self.assert_tainted("async def handler(request: Request):\n    value = request.query_params.get('value')\n    exec(value)", "exec")

    def test_environment_subscript_to_sink(self) -> None:
        """Track direct os.environ access into a network sink."""
        self.assert_tainted("url = os.environ['CALLBACK_URL']\nrequests.post(url)", "requests.post")

    def test_django_annotated_alias_to_sink(self) -> None:
        """Track a Django HttpRequest parameter with an arbitrary local name."""
        self.assert_tainted("def handler(req: django.http.HttpRequest):\n    path = req.GET['path']\n    open(path)", "open")

    def test_framework_request_does_not_taint_literal_sink(self) -> None:
        """A request parameter does not taint a sink with a constant argument."""
        self.assert_clean("def handler(req: Request):\n    value = req.query_params['x']\n    open('fixed.txt')")

    def test_literal_reassignment_clears_taint(self) -> None:
        """A known literal assignment removes tracked taint."""
        self.assert_clean("x = input()\nx = 'safe'\neval(x)")

    def test_parameterized_sql_is_not_tainted_query(self) -> None:
        """Parameters do not alter SQL syntax."""
        self.assert_clean("x = request.args.get('x')\ncursor.execute('SELECT * FROM t WHERE id=?', (x,))")

    def test_literal_url_is_safe(self) -> None:
        """A fixed URL does not inherit taint from another variable."""
        self.assert_clean("x = input()\nrequests.get('https://example.com')")

    def test_plain_variable_is_not_a_source(self) -> None:
        """An unknown local variable alone is not proven tainted."""
        self.assert_clean("x = config_value\nopen(x)")

    def test_other_language_is_ignored(self) -> None:
        """Python taint analysis does not parse JavaScript."""
        self.assertEqual(analyze_taint("const x = input(); eval(x)", "javascript"), [])
