"""Benign, offline API probes for EVIDENT-Bench.

Each probe is a small use of a public API of a vulnerable package version. `M` stands for the
package's top-level module (aliased differently by different code patterns). Whether a probe
executes a vulnerable function is *not* assumed here: it is measured by tracing the probe against
the vulnerable symbols mined from the advisories' fix commits.
"""

PACKAGES = [
    {"dist": "pyjwt", "version": "2.3.0", "top": "jwt", "imports": [], "probes": {
        "encode": ["return M.encode({'a': 1}, 'k' * 32, algorithm='HS256')"],
        "decode": ["t = M.encode({'a': 1}, 'k' * 32, algorithm='HS256')",
                   "return M.decode(t, 'k' * 32, algorithms=['HS256'])"],
        "header": ["t = M.encode({'a': 1}, 'k' * 32, algorithm='HS256')", "return M.get_unverified_header(t)"],
        "jwkclient": ["return M.PyJWKClient('https://example.invalid/jwks.json')"],
    }},
    {"dist": "sqlparse", "version": "0.4.3", "top": "sqlparse", "imports": [], "probes": {
        "format": ["return M.format('select a, b from t where x = 1 -- c', reindent=True, keyword_case='upper')"],
        "parse": ["return M.parse('select * from t; insert into t values (1)')"],
        "split": ["return M.split('select 1; select 2;')"],
        "strip": ["return M.format('/* x */ select 1 -- y', strip_comments=True)"],
    }},
    {"dist": "jinja2", "version": "3.1.2", "top": "jinja2", "imports": ["jinja2.sandbox"], "probes": {
        "render": ["return M.Template('Hello {{ name }}!').render(name='x')"],
        "xmlattr": ["e = M.Environment(autoescape=True)",
                    "return e.from_string('<a{{ d|xmlattr }}>').render(d={'class': 'c', 'id': 'i'})"],
        "sandbox": ["return M.sandbox.SandboxedEnvironment().from_string('{{ 1 + 2 }}').render()"],
        "loader": ["e = M.Environment(loader=M.DictLoader({'a.html': 'A {{ x }}'}))",
                   "return e.get_template('a.html').render(x=1)"],
    }},
    {"dist": "werkzeug", "version": "2.2.2", "top": "werkzeug", "imports": [
        "werkzeug.http", "werkzeug.utils", "werkzeug.security", "werkzeug.formparser", "werkzeug.test"], "probes": {
        "options": ["return M.http.parse_options_header('text/html; charset=utf-8')"],
        "filename": ["return M.utils.secure_filename('my file.txt')"],
        "safejoin": ["return M.security.safe_join('/srv', 'a', 'b.txt')"],
        "multipart": ["b = M.test.EnvironBuilder(method='POST', data={'a': '1', 'f': (__import__('io').BytesIO(b'x'), 'f.txt')})",
                      "return M.formparser.parse_form_data(b.get_environ())"],
        "cookie": ["return M.http.parse_cookie('a=b; c=d')"],
    }},
    {"dist": "urllib3", "version": "1.26.5", "top": "urllib3", "imports": ["urllib3.util", "urllib3.util.retry"], "probes": {
        "parseurl": ["return M.util.parse_url('http://user@a.example:8080/b?c=d#e')"],
        "retry": ["r = M.util.retry.Retry(total=3, redirect=2)", "return r.new(total=2).remove_headers_on_redirect"],
        "pool": ["return M.PoolManager(num_pools=1).connection_from_url('http://localhost:9')"],
        "response": ["return M.response.HTTPResponse(body=__import__('io').BytesIO(b'xy'), headers={'a': 'b'}, preload_content=False).read()"],
    }},
    {"dist": "requests", "version": "2.28.1", "top": "requests", "imports": ["requests.utils"], "probes": {
        "prepare": ["return M.Request('GET', 'http://example.invalid/x', params={'a': '1'}).prepare()"],
        "proxies": ["s = M.Session()", "p = M.Request('GET', 'http://example.invalid/x').prepare()",
                    "return s.rebuild_proxies(p, {})"],
        "requote": ["return M.utils.requote_uri('http://example.invalid/a b')"],
        "merge": ["return M.Session().merge_environment_settings('http://example.invalid', {}, None, False, None)"],
    }},
    {"dist": "idna", "version": "3.6", "top": "idna", "imports": [], "probes": {
        "encode": ["return M.encode('example.com')"],
        "decode": ["return M.decode('xn--bcher-kva.example')"],
        "uts46": ["return M.encode('Bücher.example', uts46=True)"],
    }},
    {"dist": "bleach", "version": "3.1.0", "top": "bleach", "imports": [], "probes": {
        "clean": ["return M.clean('<b>x</b><script>y</script>')"],
        "linkify": ["return M.linkify('see http://example.com now')"],
        "clean_tags": ["return M.clean('<noscript><b>x</b></noscript>', tags=['b', 'noscript'])"],
    }},
    {"dist": "pygments", "version": "2.11.0", "top": "pygments", "imports": [
        "pygments.lexers", "pygments.formatters"], "probes": {
        "python": ["return M.highlight('x = 1', M.lexers.PythonLexer(), M.formatters.HtmlFormatter())"],
        "byname": ["return M.lexers.get_lexer_by_name('sql')"],
        "smithy": ["return list(M.lexers.get_lexer_by_name('smithy').get_tokens('namespace a.b'))"],
    }},
    {"dist": "babel", "version": "2.9.0", "top": "babel", "imports": ["babel.dates", "babel.localedata", "babel.numbers"], "probes": {
        "locale": ["return M.Locale.parse('en_US').display_name"],
        "load": ["return M.localedata.load('en_US')['languages']['fr']"],
        "number": ["return M.numbers.format_decimal(1234.5, locale='en_US')"],
    }},
    {"dist": "tornado", "version": "6.3.2", "top": "tornado", "imports": ["tornado.httputil", "tornado.escape"], "probes": {
        "headers": ["return M.httputil.HTTPHeaders.parse('A: b\\r\\nC: d\\r\\n')"],
        "cookie": ["return M.httputil.parse_cookie('a=b; c=d')"],
        "body": ["a, f = {}, {}",
                 "M.httputil.parse_body_arguments('application/x-www-form-urlencoded', b'a=1&b=2', a, f)",
                 "return a"],
        "escape": ["return M.escape.url_unescape('a%20b')"],
    }},
    {"dist": "python-multipart", "version": "0.0.6", "top": "multipart", "imports": ["multipart.multipart"], "probes": {
        "options": ["return M.multipart.parse_options_header('form-data; name=\"x\"; filename=\"y\"')"],
        "qs": ["p = M.multipart.QuerystringParser({})", "p.write(b'a=1&b=2')", "return p.finalize()"],
    }},
    {"dist": "mako", "version": "1.2.1", "top": "mako", "imports": ["mako.template", "mako.lookup"], "probes": {
        "render": ["return M.template.Template('hello ${x}').render(x=1)"],
        "lookup": ["return M.lookup.TemplateLookup()"],
    }},
    {"dist": "jsonpickle", "version": "1.4.1", "top": "jsonpickle", "imports": [], "probes": {
        "encode": ["return M.encode({'a': [1, 2]})"],
        "decode": ["return M.decode('{\"a\": [1, 2]}')"],
    }},
    {"dist": "tqdm", "version": "4.66.2", "top": "tqdm", "imports": ["tqdm.cli"], "probes": {
        "bar": ["return sum(M.tqdm(range(3), disable=True))"],
        "cast": ["return M.cli.cast('3', 'int')"],
    }},
    {"dist": "markdown", "version": "3.3.4", "top": "markdown", "imports": [], "probes": {
        "md": ["return M.markdown('# T\\n\\n*x*')"],
    }},
    {"dist": "certifi", "version": "2022.9.24", "top": "certifi", "imports": [], "probes": {
        "where": ["return M.where()"],
    }},
    {"dist": "setuptools", "version": "65.5.0", "top": "setuptools", "imports": ["setuptools.package_index"], "probes": {
        "index": ["return M.package_index.PackageIndex(index_url='https://example.invalid/simple')"],
        "egg": ["return M.package_index.egg_info_for_url('https://example.invalid/a-1.0.tar.gz#egg=a')"],
    }},
    {"dist": "aiohttp", "version": "3.8.5", "top": "aiohttp", "imports": ["aiohttp.helpers", "aiohttp.http"], "probes": {
        "basicauth": ["return M.BasicAuth('u', 'p').encode()"],
        "url": ["return M.helpers.parse_mimetype('text/html; charset=utf-8')"],
    }},
    {"dist": "django", "version": "4.1.3", "top": "django", "imports": [
        "django.conf", "django.utils.html", "django.utils.text", "django.utils.http", "django.utils.encoding",
        "django.utils.dateparse", "django.utils.numberformat", "django.core.validators", "django.template"], "probes": {
        "strip_tags": ["M.conf.settings.configured or M.conf.settings.configure()",
                       "return M.utils.html.strip_tags('<b>x</b><i>y</i>')"],
        "truncator": ["M.conf.settings.configured or M.conf.settings.configure()",
                      "return M.utils.text.Truncator('<p>a b c d</p>').words(2, html=True)"],
        "urlize": ["M.conf.settings.configured or M.conf.settings.configure()",
                   "return M.utils.html.urlize('see http://example.com now')"],
        "uri_to_iri": ["return M.utils.encoding.uri_to_iri('/a%20b')"],
        "safe_url": ["return M.utils.http.url_has_allowed_host_and_scheme('http://a.example/x', {'a.example'})"],
        "duration": ["return M.utils.dateparse.parse_duration('P1DT2H')"],
        "numformat": ["M.conf.settings.configured or M.conf.settings.configure()",
                      "return M.utils.numberformat.format(1234567.891, '.', 2, 3, ',', True)"],
        "email": ["M.conf.settings.configured or M.conf.settings.configure()",
                  "return M.core.validators.EmailValidator()('a@b.example')"],
        "template": ["M.conf.settings.configured or M.conf.settings.configure()",
                     "e = M.template.Engine()",
                     "return e.from_string('{{ x|floatformat:2 }} {{ s|wordwrap:5 }}').render(M.template.Context({'x': 1.5, 's': 'abc def ghi'}))"],
    }},
    {"dist": "pypdf", "version": "3.9.0", "top": "pypdf", "imports": [], "probes": {
        "write": ["w = M.PdfWriter()", "w.add_blank_page(72, 72)", "b = __import__('io').BytesIO()", "w.write(b)",
                  "return len(b.getvalue())"],
        "read": ["w = M.PdfWriter()", "w.add_blank_page(72, 72)", "b = __import__('io').BytesIO()", "w.write(b)",
                 "r = M.PdfReader(__import__('io').BytesIO(b.getvalue()))", "return len(r.pages)"],
        "text": ["w = M.PdfWriter()", "w.add_blank_page(72, 72)", "b = __import__('io').BytesIO()", "w.write(b)",
                 "r = M.PdfReader(__import__('io').BytesIO(b.getvalue()))", "return r.pages[0].extract_text()"],
        "meta": ["w = M.PdfWriter()", "w.add_metadata({'/Title': 'x'})", "return w"],
    }},
    {"dist": "flask", "version": "2.2.2", "top": "flask", "imports": [], "probes": {
        "client": ["app = M.Flask('bench')", "app.add_url_rule('/', 'i', lambda: 'ok')",
                   "return app.test_client().get('/').status_code"],
        "session": ["app = M.Flask('bench')", "app.secret_key = 'k'",
                    "app.add_url_rule('/', 'i', lambda: (M.session.__setitem__('a', 1), 'ok')[1])",
                    "return app.test_client().get('/').headers.get('Vary')"],
        "jsonify": ["app = M.Flask('bench')", "ctx = app.app_context()", "ctx.push()",
                    "r = M.jsonify(a=1)", "ctx.pop()", "return r.status_code"],
    }},
    {"dist": "waitress", "version": "2.1.1", "top": "waitress", "imports": ["waitress.parser", "waitress.adjustments"], "probes": {
        "parse": ["p = M.parser.HTTPRequestParser(M.adjustments.Adjustments())",
                  "p.received(b'GET / HTTP/1.1\\r\\nHost: a\\r\\n\\r\\n')", "return p.completed"],
        "chunked": ["p = M.parser.HTTPRequestParser(M.adjustments.Adjustments())",
                    "p.received(b'POST / HTTP/1.1\\r\\nHost: a\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\nx\\r\\n0\\r\\n\\r\\n')",
                    "return p.completed"],
        "adjust": ["return M.adjustments.Adjustments(port=8080).port"],
    }},
    {"dist": "starlette", "version": "0.25.0", "top": "starlette", "imports": ["starlette.datastructures", "starlette.requests"], "probes": {
        "url": ["return M.datastructures.URL('http://a.example/b?c=d').replace(path='/e')"],
        "headers": ["return M.datastructures.Headers({'a': 'b'})"],
        "form": ["return M.datastructures.FormData([('a', '1')])"],
    }},
]
