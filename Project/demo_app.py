# demo_app.py
# Simple local demo web app with a simulated SQLi-like endpoint and a reflected XSS endpoint.
from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Home page
@app.route('/')
def index():
    return """
    <h2>Demo Vulnerable App (Local)</h2>
    <ul>
      <li><a href="/search?q=test">Reflected XSS demo ( /search )</a></li>
      <li><a href="/item?id=1">SQLi-like demo ( /item )</a></li>
      <li><a href="/login">Login (form)</a></li>
    </ul>
    <p>Scanner demo target: <strong>http://127.0.0.1:5000</strong></p>
    """

# Reflected XSS endpoint (unsafe on purpose for lab)
@app.route('/search')
def search():
    q = request.args.get('q', '')
    # intentionally reflect user input without escaping (for demo only)
    html = f"""
    <h3>Search results for: {q}</h3>
    <p>This page reflects the query param directly (for demo)</p>
    <form method="get" action="/search">
      <input name="q" value="{q}">
      <input type="submit" value="Search">
    </form>
    """
    return render_template_string(html)

# Simulated SQLi endpoint (no real DB) - demonstrates an "error" string
@app.route('/item')
def item():
    item_id = request.args.get('id', '')
    # Simulate an error message when quotes present - detector looks for error strings
    if "'" in item_id or '"' in item_id:
        # Fake DB-like error string returned (detectors look for such patterns)
        return "You have an error in your SQL syntax near '{}'".format(item_id), 200
    # Normal behaviour
    return f"<h3>Item page for id = {item_id}</h3><p>Normal content.</p>", 200

# Simple login form (POST)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username','')
        p = request.form.get('password','')
        # no real auth: echo back (benign)
        return f"<p>Attempted login for {u}</p>"
    return '''
      <h3>Login</h3>
      <form method="post" action="/login">
        <input name="username" type="text" value="">
        <input name="password" type="password" value="">
        <input type="submit" value="Login">
      </form>
    '''

if __name__ == '__main__':
    # use debug False for realism (but local demo)
    app.run(host='127.0.0.1', port=5000, debug=False)
    print("This detector will only run in LAB mode. Start with --lab or set LAB_MODE=1 environment variable.")
#         return