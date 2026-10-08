// Package farmexport writes reviewed Python exploits to an optional
// DestructiveFarm client directory. It never executes submitted code.
package farmexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const maxExploitSize = 1 << 20

const pythonASTValidator = `
import ast
import re
import sys

try:
    tree = ast.parse(sys.stdin.read())
except SyntaxError:
    print("invalid Python syntax", file=sys.stderr)
    sys.exit(2)

parents = {}
for parent in ast.walk(tree):
    for child in ast.iter_child_nodes(parent):
        parents[child] = parent

http_methods = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
cookie_methods = {"set", "clear", "get", "update", "set_cookie"}
header_methods = {"get", "update", "items", "keys", "values"}
reflection_calls = {"eval", "exec", "compile", "__import__", "getattr", "setattr", "delattr", "globals", "locals", "vars", "breakpoint", "input", "open"}
dangerous_calls = {"system", "popen", "spawn", "fork", "forkpty", "connect", "send", "sendall", "urlopen", "mount", "proxy_manager_for", "get_connection", "get_connection_with_tls_context", "connection_from_url", "connection_from_host"}
dangerous_calls.update({"execv", "execve", "execl", "execlp", "execle", "execlpe", "execvp", "execvpe", "posix_spawn", "posix_spawnp", "startfile"})
dangerous_segments = {"builtins", "ctypes", "ftplib", "importlib", "io", "os", "pathlib", "pickle", "shutil", "smtplib", "socket", "ssl", "subprocess", "sys", "telnetlib", "tempfile"}
allowed_from_imports = {
    "http.cookies": {"SimpleCookie"},
    "urllib.parse": {"parse_qs", "parse_qsl", "quote", "quote_plus", "unquote", "unquote_plus", "urlencode", "urlparse"},
}
allowed_imports = {"base64", "collections", "datetime", "hashlib", "html", "http.cookies", "itertools", "json", "random", "re", "requests", "secrets", "string", "sys", "time", "urllib.parse", "uuid"}

def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    return []

def is_direct_call(node):
    parent = parents.get(node)
    return isinstance(parent, ast.Call) and parent.func is node

def reject(message):
    raise ValueError(message)

def top_level_store(name, required):
    matches = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id == name:
                matches.append(target)
    if (required and len(matches) != 1) or (not required and len(matches) > 1):
        reject(name + " must have one top-level assignment")
    return matches[0] if matches else None

def safe_request_url(node, has_target):
    if not isinstance(node, ast.JoinedStr) or len(node.values) < 2:
        return False
    first, host = node.values[0], node.values[1]
    if not isinstance(first, ast.Constant) or first.value not in {"http://", "https://"}:
        return False
    if not isinstance(host, ast.FormattedValue) or not isinstance(host.value, ast.Name):
        return False
    if host.value.id not in {"IP", "TARGET"} or (host.value.id == "TARGET" and not has_target):
        return False
    if len(node.values) == 2:
        return True
    suffix_node = node.values[2]
    if not isinstance(suffix_node, ast.Constant) or not isinstance(suffix_node.value, str):
        return False
    suffix = suffix_node.value
    if suffix.startswith(":"):
        match = re.match(r"^:([0-9]{1,5})(.*)$", suffix, re.S)
        if match is None or not 1 <= int(match.group(1)) <= 65535:
            return False
        suffix = match.group(2)
    if suffix == "":
        return len(node.values) == 3
    return suffix.startswith("/")

def validate_tree():
    ip_store = top_level_store("IP", True)
    session_store = top_level_store("s", True)
    target_store = top_level_store("TARGET", False)
    ip_assignment = parents.get(ip_store)
    argv_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and dotted(node) == ["sys", "argv"]]
    argv_value = ip_assignment.value if isinstance(ip_assignment, ast.Assign) else None
    argv_slice = argv_value.slice if isinstance(argv_value, ast.Subscript) else None
    if isinstance(argv_slice, ast.Index):
        argv_slice = argv_slice.value
    if len(argv_nodes) != 1 or not isinstance(argv_value, ast.Subscript) or argv_value.value is not argv_nodes[0] or not isinstance(argv_slice, ast.Constant) or argv_slice.value != 1:
        reject("sys.argv[1] may only initialize IP")
    trust_targets = []
    for statement in tree.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if dotted(target) == ["s", "trust_env"] and isinstance(statement.value, ast.Constant) and statement.value.value is False:
            trust_targets.append(target)
    if len(trust_targets) != 1:
        reject("s.trust_env must be set to False once at top level")

    allowed_stores = {id(ip_store), id(session_store)}
    if target_store is not None:
        allowed_stores.add(id(target_store))
    protected = {"IP", "TARGET", "s", "requests", "sys", "print"}

    class Guard(ast.NodeVisitor):
        def visit_Import(self, node):
            for item in node.names:
                if item.name not in allowed_imports:
                    reject("import is outside the module allowlist")
                if item.asname is not None:
                    reject("import aliases are not allowed")
                bound = item.asname or item.name.split(".")[0]
                if bound in protected and not (item.asname is None and item.name in {"requests", "sys"}):
                    reject("protected name import alias")
                if item.name in {"requests", "sys"} and item.asname is not None:
                    reject("requests/sys import alias")
            self.generic_visit(node)

        def visit_ImportFrom(self, node):
            allowed = allowed_from_imports.get(node.module, set()) if node.level == 0 else set()
            for item in node.names:
                if item.asname is not None or item.name not in allowed:
                    reject("from-import is outside the symbol allowlist")
                if (item.asname or item.name) in protected:
                    reject("protected name from-import")
            self.generic_visit(node)

        def visit_FunctionDef(self, node):
            if node.name in protected:
                reject("protected name function binding")
            self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            if node.name in protected:
                reject("protected name class binding")
            self.generic_visit(node)

        def visit_arg(self, node):
            if node.arg in protected:
                reject("protected name function argument")
            self.generic_visit(node)

        def visit_Global(self, node):
            if protected.intersection(node.names):
                reject("protected name global declaration")

        def visit_Nonlocal(self, node):
            if protected.intersection(node.names):
                reject("protected name nonlocal declaration")

        def visit_ExceptHandler(self, node):
            if node.name in protected:
                reject("protected exception binding")
            self.generic_visit(node)

        def visit_MatchAs(self, node):
            if node.name in protected:
                reject("protected match binding")
            self.generic_visit(node)

        def visit_MatchStar(self, node):
            if node.name in protected:
                reject("protected match binding")
            self.generic_visit(node)

        def visit_Name(self, node):
            if node.id.startswith("__"):
                reject("private name")
            if isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in protected and id(node) not in allowed_stores:
                reject("protected name reassignment: " + node.id)
            if node.id in reflection_calls and isinstance(parents.get(node), ast.Call):
                reject("reflection call")
            if node.id in {"s", "requests"} and isinstance(node.ctx, ast.Load) and not isinstance(parents.get(node), ast.Attribute):
                reject("session/module alias")
            if node.id == "r" and isinstance(node.ctx, ast.Load) and not isinstance(parents.get(node), ast.Attribute):
                reject("response object alias")
            self.generic_visit(node)

        def visit_Attribute(self, node):
            parts = dotted(node)
            if node.attr.startswith("_"):
                reject("private attribute")
            if node.attr in dangerous_calls:
                reject("dangerous method")
            if node.attr == "request" and parts != ["s", "request"]:
                reject("non-Session request method")
            if parts and parts[0] != "sys" and dangerous_segments.intersection(parts[1:]):
                reject("module escape through an allowed import")
            if parts and parts[0] == "r" and len(parts) > 1 and parts[1] in {"connection", "raw", "request", "next"}:
                reject("response transport access")
            if node.attr == "Session" and parts != ["requests", "Session"]:
                reject("unapproved Session constructor")
            if parts and parts[0] == "requests":
                if parts != ["requests", "Session"] or not is_direct_call(node):
                    reject("requests internals")
            if parts and parts[0] == "sys" and parts not in (["sys", "argv"], ["sys", "stderr"]):
                reject("sys internals")
            if parts and parts[0] == "s":
                allowed = False
                if len(parts) == 2 and parts[1] in http_methods and is_direct_call(node):
                    allowed = True
                elif parts == ["s", "cookies"]:
                    allowed = True
                elif len(parts) == 3 and parts[1] == "cookies" and parts[2] in cookie_methods and is_direct_call(node):
                    allowed = True
                elif parts == ["s", "headers"]:
                    allowed = True
                elif len(parts) == 3 and parts[1] == "headers" and parts[2] in header_methods and is_direct_call(node):
                    allowed = True
                elif id(node) == id(trust_targets[0]):
                    allowed = True
                if not allowed:
                    reject("unsupported Session access")
            self.generic_visit(node)

        def visit_Assign(self, node):
            for target in node.targets:
                parts = dotted(target)
                if parts and parts[0] == "s" and not (parts == ["s"] or id(target) == id(trust_targets[0])):
                    reject("Session mutation")
            if dotted(node.value) and dotted(node.value)[0] in {"s", "requests"}:
                reject("session/module alias")
            self.generic_visit(node)

        def visit_AnnAssign(self, node):
            if node.value is not None and dotted(node.value) and dotted(node.value)[0] in {"s", "requests"}:
                reject("session/module alias")
            self.generic_visit(node)

        def visit_Call(self, node):
            if isinstance(node.func, ast.Name) and node.func.id in reflection_calls:
                reject("reflection call")
            for argument in [*node.args, *[item.value for item in node.keywords]]:
                if isinstance(argument, ast.Name) and argument.id in {"s", "requests"}:
                    reject("session/module passed as argument")
            parts = dotted(node.func)
            if len(parts) == 2 and parts[0] == "s" and parts[1] in http_methods:
                keywords = {item.arg: item.value for item in node.keywords if item.arg is not None}
                if any(item.arg is None for item in node.keywords):
                    reject("expanded request kwargs")
                if {"proxies", "hooks", "cert", "auth"}.intersection(keywords):
                    reject("unsafe request kwargs")
                redirects = keywords.get("allow_redirects")
                if not (isinstance(redirects, ast.Constant) and redirects.value is False):
                    reject("allow_redirects=False is required")
                target_index = 1 if parts[1] == "request" else 0
                if len(node.args) != target_index + 1:
                    reject("request optional arguments must use keywords")
                if len(node.args) <= target_index or not safe_request_url(node.args[target_index], target_store is not None):
                    reject("request target must be an inline IP/TARGET f-string")
            self.generic_visit(node)

    Guard().visit(tree)

try:
    validate_tree()
except ValueError as error:
    print(str(error), file=sys.stderr)
    sys.exit(3)
`

var (
	filenamePattern         = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}[.]py$`)
	argvPattern             = regexp.MustCompile(`(?m)^[ \t]*IP[ \t]*=[ \t]*sys[.]argv\[1\][ \t]*$`)
	ipAssignmentPattern     = regexp.MustCompile(`(?m)^[ \t]*IP[ \t]*=`)
	targetAssignmentPattern = regexp.MustCompile(`(?m)^[ \t]*TARGET[ \t]*=`)
	targetNormalization     = regexp.MustCompile(`(?m)^[ \t]*TARGET[ \t]*=[ \t]*f'\[\{IP\}\]'[ \t]+if[ \t]+':'[ \t]+in[ \t]+IP[ \t]+and[ \t]+not[ \t]+IP[.]startswith\('\['\)[ \t]+else[ \t]+IP[ \t]*$`)
	sessionPattern          = regexp.MustCompile(`(?m)^[ \t]*s[ \t]*=[ \t]*requests[.]Session\([ \t]*\)[ \t]*$`)
	trustEnvPattern         = regexp.MustCompile(`(?m)^[ \t]*s[.]trust_env[ \t]*=[ \t]*False[ \t]*$`)
	sessionCallPattern      = regexp.MustCompile(`requests[.]Session\([ \t]*\)`)
	requestPattern          = regexp.MustCompile(`\bs[ \t]*[.][ \t]*(get|post|put|patch|delete|head|options|request)[ \t]*\(`)
	assignmentPrefixPattern = regexp.MustCompile(`^([ \t]*)r[ \t]*=[ \t]*$`)
	exactPrintPattern       = regexp.MustCompile(`(?m)^([ \t]*)print[ \t]*\([ \t]*r[ \t]*[.][ \t]*text[ \t]*,[ \t]*flush[ \t]*=[ \t]*True[ \t]*\)[ \t]*$`)
	importPattern           = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([^\n#]+)`)
	fromImportPattern       = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+([A-Za-z_]\w*(?:[.]\w+)*)[ \t]+import[ \t]+`)
	allowedTargetPrefix     = regexp.MustCompile(`^https?://\{(?:IP|TARGET)\}(?::\d{1,5})?(?:/|$)`)
	dangerousPattern        = regexp.MustCompile(`\b(?:eval|exec|compile|__import__|open|breakpoint|input)[ \t]*\(|\b(?:os|subprocess|socket|shutil|pathlib|ctypes|ftplib|smtplib|telnetlib)[ \t]*[.]|\b(?:http[ \t]*[.][ \t]*client|urllib[ \t]*[.][ \t]*request|urlopen|HTTPConnection|HTTPSConnection)\b|\brequests[ \t]*[.][ \t]*(?:get|post|put|patch|delete|head|options|request|send)[ \t]*\(|\bs[ \t]*[.][ \t]*send[ \t]*\(|\bsys[ \t]*[.][ \t]*stdout[ \t]*[.][ \t]*write[ \t]*\(`)
)

var errUnsupportedMediaType = errors.New("Content-Type must be application/json")

type request struct {
	Name string
	Code string
}

type response struct {
	Available bool
	Valid     bool   `json:",omitempty"`
	Filename  string `json:",omitempty"`
	Error     string `json:",omitempty"`
}

func RegisterRoutes(router chi.Router) {
	directory := os.Getenv("PKAPPA2_FARM_EXPORT_DIR")
	router.Get("/api/farm-export", statusHandler(directory))
	router.Post("/api/farm-export/validate", validationHandler())
	router.Post("/api/farm-export", exportHandler(directory))
}

func validationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := decodeRequest(w, r)
		if err != nil {
			writeDecodeError(w, err)
			return
		}
		if err := validate(payload); err != nil {
			writeJSON(w, http.StatusBadRequest, response{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, response{Valid: true})
	}
}

func statusHandler(directory string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, response{Available: directoryAvailable(directory)})
	}
}

func exportHandler(directory string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !directoryAvailable(directory) {
			writeJSON(w, http.StatusServiceUnavailable, response{
				Error: "DestructiveFarm export directory is not configured or writable",
			})
			return
		}

		payload, err := decodeRequest(w, r)
		if err != nil {
			writeDecodeError(w, err)
			return
		}
		if err := validate(payload); err != nil {
			writeJSON(w, http.StatusBadRequest, response{Error: err.Error()})
			return
		}

		fullPath := filepath.Join(directory, payload.Name)
		file, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				writeJSON(w, http.StatusConflict, response{Error: "an exploit with this filename already exists"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, response{Error: "failed to create exploit file"})
			return
		}
		if _, err := file.WriteString(payload.Code); err != nil {
			_ = file.Close()
			_ = os.Remove(fullPath)
			writeJSON(w, http.StatusInternalServerError, response{Error: "failed to write exploit file"})
			return
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(fullPath)
			writeJSON(w, http.StatusInternalServerError, response{Error: "failed to finish exploit file"})
			return
		}
		writeJSON(w, http.StatusCreated, response{Available: true, Filename: payload.Name})
	}
}

func decodeRequest(w http.ResponseWriter, r *http.Request) (request, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return request{}, errUnsupportedMediaType
	}
	body := http.MaxBytesReader(w, r.Body, maxExploitSize)
	defer body.Close()
	var payload request
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return request{}, err
	}
	return payload, nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errUnsupportedMediaType) {
		writeJSON(w, http.StatusUnsupportedMediaType, response{Error: errUnsupportedMediaType.Error()})
		return
	}
	writeJSON(w, http.StatusBadRequest, response{Error: "invalid export request"})
}

func directoryAvailable(directory string) bool {
	if directory == "" || !filepath.IsAbs(directory) {
		return false
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return false
	}
	test, err := os.CreateTemp(directory, ".pkappa2-write-test-")
	if err != nil {
		return false
	}
	name := test.Name()
	_ = test.Close()
	_ = os.Remove(name)
	return true
}

func validate(payload request) error {
	if !filenamePattern.MatchString(payload.Name) || filepath.Base(payload.Name) != payload.Name {
		return fmt.Errorf("invalid exploit filename")
	}
	if payload.Code == "" || len(payload.Code) > maxExploitSize {
		return fmt.Errorf("exploit code must be between 1 byte and 1 MiB")
	}
	if !strings.HasPrefix(payload.Code, "#!/usr/bin/env python3") {
		return fmt.Errorf("exploit must start with #!/usr/bin/env python3")
	}
	masked := maskPython(payload.Code)
	if err := validateImports(masked); err != nil {
		return err
	}
	if !argvPattern.MatchString(masked) || len(ipAssignmentPattern.FindAllStringIndex(masked, -1)) != 1 {
		return fmt.Errorf("exploit must contain IP = sys.argv[1]")
	}
	targetAssignmentMatches := targetAssignmentPattern.FindAllStringIndex(masked, -1)
	targetAssignments := len(targetAssignmentMatches)
	if targetAssignments > 0 {
		validTarget := targetAssignments == 1
		if validTarget {
			lineStart := targetAssignmentMatches[0][0]
			lineEnd := strings.IndexByte(payload.Code[lineStart:], '\n')
			if lineEnd < 0 {
				lineEnd = len(payload.Code)
			} else {
				lineEnd += lineStart
			}
			validTarget = targetNormalization.MatchString(payload.Code[lineStart:lineEnd])
		}
		if !validTarget {
			return fmt.Errorf("TARGET may only contain the standard IPv6 normalization")
		}
	}
	if !sessionPattern.MatchString(masked) {
		return fmt.Errorf("exploit must contain s = requests.Session()")
	}
	if len(sessionCallPattern.FindAllStringIndex(masked, -1)) != 1 {
		return fmt.Errorf("exploit must create exactly one requests.Session()")
	}
	if len(trustEnvPattern.FindAllStringIndex(masked, -1)) != 1 {
		return fmt.Errorf("exploit must contain s.trust_env = False")
	}
	if dangerousPattern.MatchString(masked) {
		return fmt.Errorf("exploit contains a dangerous process or code execution call")
	}
	if err := validateRequests(payload.Code, masked, targetAssignments == 1); err != nil {
		return err
	}
	return validatePythonSyntax(payload.Code)
}

func validatePythonSyntax(source string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-I", "-S", "-c", pythonASTValidator)
	command.Stdin = strings.NewReader(source)
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 3 {
		reason := strings.TrimSpace(string(output))
		if len(reason) > 240 {
			reason = reason[:240]
		}
		return fmt.Errorf("exploit violates export policy: %s", reason)
	}
	if err != nil {
		return fmt.Errorf("exploit is not valid Python syntax")
	}
	return nil
}

func validateImports(masked string) error {
	allowed := map[string]bool{
		"base64": true, "collections": true, "datetime": true, "hashlib": true,
		"html": true, "http.cookies": true, "itertools": true, "json": true,
		"random": true, "re": true, "requests": true, "secrets": true,
		"string": true, "sys": true, "time": true,
		"urllib.parse": true, "uuid": true,
	}
	seen := map[string]bool{}
	for _, match := range importPattern.FindAllStringSubmatch(masked, -1) {
		for _, item := range strings.Split(match[1], ",") {
			fields := strings.Fields(item)
			if len(fields) == 0 {
				continue
			}
			module := fields[0]
			if !allowed[module] {
				return fmt.Errorf("import is outside the exploit allowlist: %s", module)
			}
			seen[strings.Split(module, ".")[0]] = true
		}
	}
	for _, match := range fromImportPattern.FindAllStringSubmatch(masked, -1) {
		module := match[1]
		if !allowed[module] {
			return fmt.Errorf("import is outside the exploit allowlist: %s", module)
		}
		seen[strings.Split(module, ".")[0]] = true
	}
	if !seen["requests"] || !seen["sys"] {
		return fmt.Errorf("exploit must import requests and sys")
	}
	return nil
}

func maskPython(source string) string {
	output := []byte(source)
	quote := byte(0)
	triple := false
	comment := false
	for i := 0; i < len(source); i++ {
		character := source[i]
		if comment {
			if character == '\n' {
				comment = false
			} else {
				output[i] = ' '
			}
			continue
		}
		if quote != 0 {
			if character != '\n' {
				output[i] = ' '
			}
			if character == '\\' {
				if i+1 < len(source) {
					i++
					if source[i] != '\n' {
						output[i] = ' '
					}
				}
				continue
			}
			if triple && i+2 < len(source) && source[i] == quote && source[i+1] == quote && source[i+2] == quote {
				output[i], output[i+1], output[i+2] = ' ', ' ', ' '
				i += 2
				quote, triple = 0, false
			} else if !triple && character == quote {
				quote = 0
			}
			continue
		}
		if character == '#' {
			comment = true
			output[i] = ' '
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			triple = i+2 < len(source) && source[i+1] == character && source[i+2] == character
			output[i] = ' '
			if triple {
				output[i+1], output[i+2] = ' ', ' '
				i += 2
			}
		}
	}
	return string(output)
}

func matchingParen(masked string, opening int) int {
	depth := 0
	for i := opening; i < len(masked); i++ {
		switch masked[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func callArgument(source, masked string, opening, closing, wanted int) string {
	parentheses, brackets, braces := 0, 0, 0
	start, current := opening+1, 0
	for i := opening + 1; i < closing; i++ {
		switch masked[i] {
		case '(':
			parentheses++
		case ')':
			parentheses--
		case '[':
			brackets++
		case ']':
			brackets--
		case '{':
			braces++
		case '}':
			braces--
		case ',':
			if parentheses == 0 && brackets == 0 && braces == 0 {
				if current == wanted {
					return strings.TrimSpace(source[start:i])
				}
				current++
				start = i + 1
			}
		}
	}
	if current == wanted {
		return strings.TrimSpace(source[start:closing])
	}
	return ""
}

func validTargetExpression(expression string) bool {
	candidate := strings.TrimSpace(expression)
	if len(candidate) < 4 || (candidate[0] != 'f' && candidate[0] != 'F') || (candidate[1] != '\'' && candidate[1] != '"') {
		return false
	}
	quote := candidate[1]
	closing := -1
	for i := 2; i < len(candidate); i++ {
		if candidate[i] == '\\' {
			i++
			continue
		}
		if candidate[i] == quote {
			closing = i
			break
		}
	}
	if closing != len(candidate)-1 {
		return false
	}
	return allowedTargetPrefix.MatchString(candidate[2:closing])
}

func immediatePrint(masked string, closing int, indent string) bool {
	position := closing + 1
	lineEnd := strings.IndexByte(masked[position:], '\n')
	if lineEnd < 0 {
		return false
	}
	lineEnd += position
	if strings.TrimSpace(masked[position:lineEnd]) != "" {
		return false
	}
	position = lineEnd + 1
	for position <= len(masked) {
		next := strings.IndexByte(masked[position:], '\n')
		end := len(masked)
		if next >= 0 {
			end = position + next
		}
		line := masked[position:end]
		if strings.TrimSpace(line) != "" {
			match := exactPrintPattern.FindStringSubmatch(line)
			return len(match) == 2 && match[1] == indent
		}
		if next < 0 {
			return false
		}
		position = end + 1
	}
	return false
}

func validateRequests(source, masked string, hasTarget bool) error {
	matches := requestPattern.FindAllStringSubmatchIndex(masked, -1)
	if len(matches) == 0 {
		return fmt.Errorf("exploit must contain at least one requests request")
	}
	for index, match := range matches {
		start := match[0]
		method := masked[match[2]:match[3]]
		lineStart := strings.LastIndex(masked[:start], "\n") + 1
		assignment := assignmentPrefixPattern.FindStringSubmatch(masked[lineStart:start])
		if len(assignment) != 2 {
			return fmt.Errorf("request %d must be assigned directly to r", index+1)
		}
		opening := strings.LastIndex(masked[start:match[1]], "(") + start
		closing := matchingParen(masked, opening)
		if opening < start || closing < 0 {
			return fmt.Errorf("request %d call is incomplete", index+1)
		}
		argument := 0
		if method == "request" {
			argument = 1
		}
		target := callArgument(source, masked, opening, closing, argument)
		if !validTargetExpression(target) {
			return fmt.Errorf("request %d target must be an inline IP f-string", index+1)
		}
		if strings.Contains(target, "{TARGET}") && !hasTarget {
			return fmt.Errorf("request %d uses TARGET without IPv6 normalization", index+1)
		}
		if !immediatePrint(masked, closing, assignment[1]) {
			return fmt.Errorf("request %d must be immediately followed by print(r.text, flush=True)", index+1)
		}
	}
	if len(exactPrintPattern.FindAllStringIndex(masked, -1)) != len(matches) {
		return fmt.Errorf("exploit must contain exactly one response print per request")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
