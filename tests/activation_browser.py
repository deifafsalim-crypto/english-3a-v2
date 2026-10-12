"""Browser activation end-to-end checks using installed Chrome and websocket-client.

The local private issuer is used through its UI. Its signing key is never read or logged.
Run from the workspace: python publish-checkout/tests/activation_browser.py
"""
import functools
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.request
import websocket

PUBLIC = Path(__file__).resolve().parents[1]
WORKSPACE = PUBLIC.parent
ISSUER = WORKSPACE / 'private-activation' / 'إصدار-أكواد-الدخول.html'
CHROME = Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe')
STORAGE = 'atomic3a-browser-activation-v1'
assert ISSUER.exists(), 'Generate the local private issuer before running this integration test.'


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class CDP:
    def __init__(self, url):
        self.ws = websocket.create_connection(url, timeout=20)
        self.sequence = 0
        self.exceptions = []

    def call(self, method, **params):
        self.sequence += 1
        current = self.sequence
        self.ws.send(json.dumps({'id': current, 'method': method, 'params': params}))
        while True:
            reply = json.loads(self.ws.recv())
            if reply.get('method') == 'Runtime.exceptionThrown':
                self.exceptions.append(reply['params']['exceptionDetails'].get('text', 'Runtime exception'))
            if reply.get('id') == current:
                assert 'error' not in reply, reply.get('error')
                return reply.get('result', {})

    def evaluate(self, expression):
        reply = self.call('Runtime.evaluate', expression=expression, awaitPromise=True, returnByValue=True)
        assert 'exceptionDetails' not in reply, 'JavaScript evaluation failed: ' + reply.get('exceptionDetails', {}).get('text', '')
        return reply.get('result', {}).get('value')

    def wait(self, expression, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.evaluate(expression):
                return
            time.sleep(.08)
        raise AssertionError('Timed out waiting for browser state: ' + expression)


handler = functools.partial(QuietHandler, directory=str(PUBLIC))
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
base = f'http://127.0.0.1:{server.server_port}/'
with socket.socket() as free_port:
    free_port.bind(('127.0.0.1', 0))
    debug_port = free_port.getsockname()[1]

profile = WORKSPACE / '.activation-browser-test'
process = subprocess.Popen([
    str(CHROME), '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--remote-allow-origins=*', f'--remote-debugging-port={debug_port}', f'--user-data-dir={profile}', 'about:blank',
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
connections = []

try:
    version = None
    for _ in range(100):
        try:
            version = json.load(urllib.request.urlopen(f'http://127.0.0.1:{debug_port}/json/version', timeout=.5))
            break
        except Exception:
            time.sleep(.1)
    assert version, 'Headless Chrome did not start.'
    browser = CDP(version['webSocketDebuggerUrl'])
    connections.append(browser)

    def new_page(url='about:blank', context=None, bootstrap=None):
        if context is None:
            context = browser.call('Target.createBrowserContext')['browserContextId']
        target = browser.call('Target.createTarget', url='about:blank', browserContextId=context)['targetId']
        tabs = json.load(urllib.request.urlopen(f'http://127.0.0.1:{debug_port}/json/list'))
        tab = next(tab for tab in tabs if tab['id'] == target)
        page = CDP(tab['webSocketDebuggerUrl'])
        connections.append(page)
        page.call('Page.enable')
        page.call('Runtime.enable')
        if bootstrap:
            page.call('Page.addScriptToEvaluateOnNewDocument', source=bootstrap)
        page.call('Page.navigate', url=url)
        return page, context

    def ready(page):
        page.wait("!!document.getElementById('activationRequest') && !!document.getElementById('activationRequest').value && !document.getElementById('activationSubmit').disabled")

    def request(page):
        return page.evaluate("document.getElementById('activationRequest').value")

    def submit(page, code):
        page.evaluate("document.getElementById('activationCode').value=" + json.dumps(code) + ";document.getElementById('activationForm').requestSubmit()")

    def active(page):
        page.wait("document.documentElement.dataset.activation === 'active' && document.getElementById('activationGate').hidden")

    def accept_rights(page):
        if page.evaluate("document.getElementById('rightsDialog').open"):
            page.evaluate("document.getElementById('rightsAccept').click()")

    issuer, _ = new_page(ISSUER.as_uri())
    issuer.wait("!!document.getElementById('issueForm') && typeof AtomicActivation === 'object'")
    assert issuer.evaluate('!!crypto.subtle'), 'Offline issuer must support Web Crypto from file://.'

    def issue(id):
        issuer.evaluate("document.getElementById('requestInput').value=" + json.dumps(id) + ";document.getElementById('issueForm').requestSubmit()")
        issuer.wait("!document.getElementById('result').hidden && !!document.getElementById('codeOutput').value")
        return issuer.evaluate("document.getElementById('codeOutput').value")

    a, context_a = new_page(base + '#/exam')
    ready(a)
    id_a = request(a)
    assert a.evaluate("document.documentElement.dataset.activation") == 'locked'
    assert a.evaluate("document.getElementById('app').children.length") == 0, 'Direct routes must stay empty while locked.'
    assert a.evaluate("getComputedStyle(document.querySelector('.nav')).display") == 'none'
    assert not a.evaluate("document.getElementById('rightsDialog').open"), 'Copyright must not obscure activation.'
    whatsapp = a.evaluate("new URL(document.getElementById('activationWhatsApp').href).searchParams.get('text')")
    assert id_a in whatsapp
    assert '96895823294' in a.evaluate("document.getElementById('activationWhatsApp').href")
    a.evaluate("Object.defineProperty(navigator, 'clipboard', {value:{writeText:async()=>{throw Error('denied')}},configurable:true});document.getElementById('activationCopy').click()")
    a.wait("document.getElementById('activationStatus').textContent.includes('محدد')")
    assert a.evaluate("document.getElementById('activationRequest').selectionEnd-document.getElementById('activationRequest').selectionStart") == len(id_a)

    # Mobile and keyboard: no overflow; locked content cannot receive focus.
    a.call('Emulation.setDeviceMetricsOverride', width=390, height=844, deviceScaleFactor=1, mobile=True)
    assert a.evaluate('document.documentElement.scrollWidth <= document.documentElement.clientWidth')
    a.evaluate("document.getElementById('activationCode').focus()")
    a.call('Input.dispatchKeyEvent', type='keyDown', key='Tab', code='Tab', windowsVirtualKeyCode=9)
    a.call('Input.dispatchKeyEvent', type='keyUp', key='Tab', code='Tab', windowsVirtualKeyCode=9)
    assert a.evaluate("document.activeElement.closest('#activationGate') !== null")
    screenshots = WORKSPACE / 'artifacts'
    screenshots.mkdir(exist_ok=True)
    import base64
    image = a.call('Page.captureScreenshot', format='png', captureBeyondViewport=True)
    (screenshots / 'activation-mobile.png').write_bytes(base64.b64decode(image['data']))

    submit(a, 'not-a-code')
    a.wait("document.getElementById('activationStatus').textContent.includes('غير صحيح')")
    assert a.evaluate("document.documentElement.dataset.activation") == 'locked'
    code_a = issue(id_a)
    submit(a, code_a)
    active(a)
    assert a.evaluate("document.getElementById('app').children.length > 0")
    assert a.evaluate("document.getElementById('rightsDialog').open")
    accept_rights(a)
    assert a.evaluate('document.activeElement.id') == 'nHome'
    a.call('Page.reload')
    active(a)
    assert not a.evaluate("document.getElementById('rightsDialog').open"), 'Rights acceptance must persist.'
    assert request(a) == id_a
    a.evaluate("location.hash='#/u/'+UNITS[0].id+'/learn'")
    a.wait("document.getElementById('app').textContent.length > 100")

    # A second browser request rejects the first code, then accepts its own.
    b, context_b = new_page(base)
    ready(b)
    id_b = request(b)
    assert id_b != id_a
    submit(b, code_a)
    b.wait("document.getElementById('activationStatus').textContent.includes('لطلب آخر')")
    assert b.evaluate("document.documentElement.dataset.activation") == 'locked'
    code_b = issue(id_b)
    submit(b, code_b)
    active(b)
    accept_rights(b)

    # Tampering with saved state must not reveal content after reload.
    b.evaluate("const s=JSON.parse(localStorage.getItem('" + STORAGE + "'));s.token='yes';localStorage.setItem('" + STORAGE + "',JSON.stringify(s))")
    b.call('Page.reload')
    ready(b)
    assert b.evaluate("document.documentElement.dataset.activation") == 'locked'
    assert b.evaluate("document.getElementById('app').children.length") == 0
    assert request(b) == id_b

    # Clearing data creates a fresh request and invalidates the previous code.
    a.evaluate('localStorage.clear()')
    a.call('Page.reload')
    ready(a)
    id_new = request(a)
    assert id_new != id_a
    submit(a, code_a)
    a.wait("document.getElementById('activationStatus').textContent.includes('لطلب آخر')")
    a.call('Emulation.setEmulatedMedia', media='print')
    assert a.evaluate("getComputedStyle(document.getElementById('app')).display") == 'none'
    a.call('Emulation.setEmulatedMedia', media='screen')

    # Matching tabs retain the same ID and receive activation through the storage event.
    sibling, _ = new_page(base, context=context_a)
    ready(sibling)
    assert request(sibling) == id_new
    submit(a, issue(id_new))
    active(a)
    active(sibling)

    # Storage-disabled browsers fail closed instead of falsely promising persistent activation.
    blocked, _ = new_page(base, bootstrap="Storage.prototype.setItem=function(){throw new DOMException('Blocked','SecurityError')}")
    blocked.wait("!!document.getElementById('activationStatus') && document.getElementById('activationStatus').textContent.includes('تعذر حفظ')")
    assert blocked.evaluate("document.getElementById('activationSubmit').disabled")
    assert blocked.evaluate("document.documentElement.dataset.activation") == 'locked'
    assert blocked.evaluate("document.getElementById('app').children.length") == 0

    # The issuer never produces output for a malformed request.
    issuer.evaluate("document.getElementById('requestInput').value='invalid';document.getElementById('issueForm').requestSubmit()")
    issuer.wait("document.getElementById('status').textContent.includes('غير صحيح')")
    assert issuer.evaluate("document.getElementById('result').hidden")
    assert all(not connection.exceptions for connection in connections), 'Unexpected browser JavaScript exception.'
    print('PASS: offline issuer, first visit, invalid code, signature verification, browser binding, refresh, rights, route navigation, clipboard fallback, mobile layout, keyboard focus, print lock, data clearing, cross-tab activation, corrupted token and blocked storage.')
finally:
    for connection in connections:
        try:
            connection.ws.close()
        except Exception:
            pass
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
    server.shutdown()
