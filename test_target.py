"""Tiny vuln-target server for end-to-end testing the scanner."""
from flask import Flask, request

app = Flask(__name__)

@app.route('/body')
def body_sink():
    """Reflects raw into HTML body — should break with <faique>."""
    q = request.args.get('q', '')
    return f"""<html><body>
    <h1>Search</h1>
    <div class='result'>You searched: {q}</div>
    </body></html>"""

@app.route('/attr')
def attr_sink():
    """Reflects into a double-quoted attribute — should break with "><faique>."""
    name = request.args.get('name', '')
    return f"""<html><body>
    <input type="text" value="{name}" />
    </body></html>"""

@app.route('/safe')
def safe_sink():
    """HTML-encoded — should NOT flag."""
    q = request.args.get('q', '')
    encoded = q.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    return f"""<html><body>
    <div>You searched: {encoded}</div>
    </body></html>"""

@app.route('/no-reflect')
def no_reflect():
    """Doesn't reflect — should be skipped."""
    return "<html><body>Hello</body></html>"

@app.route('/js')
def js_sink():
    """Reflects into a JS string — should break with quote payloads."""
    q = request.args.get('q', '')
    return f"""<html><body>
    <script>var search = "{q}"; console.log(search);</script>
    </body></html>"""

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=9999, debug=False)
