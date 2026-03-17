from __future__ import annotations

import json
import socket
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import cutter
from PySide6.QtCore import QObject, SIGNAL
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)


PLUGIN_VERSION = "0.4.0"
_CMD_LOCK = threading.RLock()
_MAX_BODY_BYTES = 1024 * 1024


class ApiError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def r2(cmd: str) -> str:
    with _CMD_LOCK:
        print(f"[MCP]: {cmd}")
        return cutter.cmd(cmd)


def r2j(cmd: str) -> Any:
    out = r2(cmd)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception as exc:
        raise ApiError(500, f"json parse failed for '{cmd}': {exc}")


def paginate(items: List[Dict[str, Any]], offset: int, limit: int) -> Dict[str, Any]:
    total = len(items)
    safe_offset = max(int(offset), 0)
    safe_limit = max(min(int(limit), 1000), 1)
    return {
        "items": items[safe_offset:safe_offset + safe_limit],
        "total": total,
        "offset": safe_offset,
        "limit": safe_limit,
    }


def _normalize_path(path: str) -> str:
    return path.rstrip("/") or "/"


def _first_query(params: Dict[str, List[str]], key: str, default: Optional[str] = None) -> Optional[str]:
    values = params.get(key)
    if not values:
        return default
    return values[0]


def _query_str(
    params: Dict[str, List[str]],
    key: str,
    default: Optional[str] = None,
    required: bool = False,
) -> Optional[str]:
    value = _first_query(params, key, default)
    if required and not value:
        raise ApiError(400, f"{key} is required")
    return value


def _query_int(
    params: Dict[str, List[str]],
    key: str,
    default: int,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    raw = _first_query(params, key)
    if raw is None or raw == "":
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            raise ApiError(400, f"{key} must be an integer")
    if minimum is not None and value < minimum:
        raise ApiError(400, f"{key} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ApiError(400, f"{key} must be <= {maximum}")
    return value


def _body_str(body: Dict[str, Any], key: str, required: bool = True) -> str:
    value = body.get(key)
    if value is None:
        if required:
            raise ApiError(400, f"{key} is required")
        return ""
    if not isinstance(value, str):
        raise ApiError(400, f"{key} must be a string")
    if required and not value:
        raise ApiError(400, f"{key} is required")
    return value


def _json_response(data: Any, status_code: int = 200) -> Tuple[int, str, bytes]:
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return status_code, "application/json; charset=utf-8", payload


def _text_response(text: str, status_code: int = 200) -> Tuple[int, str, bytes]:
    return status_code, "text/plain; charset=utf-8", text.encode("utf-8")


def _html_response(html: str, status_code: int = 200) -> Tuple[int, str, bytes]:
    return status_code, "text/html; charset=utf-8", html.encode("utf-8")


def health_endpoint(_: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    try:
        current_addr = r2("s").strip()
    except Exception:
        current_addr = ""
    return _json_response({"status": "ok", "current_address": current_addr})


def list_functions_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    offset = _query_int(params, "offset", 0, minimum=0)
    limit = _query_int(params, "limit", 100, minimum=1, maximum=1000)
    funcs = r2j("aflj") or []
    mapped = [
        {
            "addr": hex(func.get("offset", 0)),
            "name": func.get("name"),
            "size": func.get("size", 0),
            "n_bb": func.get("nbbs", 0),
        }
        for func in funcs
    ]
    return _json_response(paginate(mapped, offset, limit))


def function_detail_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    addr = _query_str(params, "addr", required=True)
    info = r2j(f"afij @ {addr}") or []
    info0 = info[0] if isinstance(info, list) and info else {}
    xrefs_in = r2j(f"axtj @ {addr}") or []
    return _json_response({"info": info0, "xrefs_in": xrefs_in})


def rename_function_endpoint(body: Dict[str, Any]) -> Tuple[int, str, bytes]:
    addr = _body_str(body, "addr")
    new_name = _body_str(body, "new_name")
    r2(f"afn {new_name} @ {addr}")
    return _json_response({"ok": True})


def decompile_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    addr = _query_str(params, "addr", required=True)
    pseudo = r2(f"pdg @ {addr}")
    return _json_response({"addr": addr, "pseudo": pseudo})


def disasm_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    addr = _query_str(params, "addr", required=True)
    fmt = _query_str(params, "fmt", "text") or "text"
    if fmt not in {"text", "json"}:
        raise ApiError(400, "fmt must be text or json")
    if fmt == "json":
        payload = r2j(f"pdfj @ {addr}") or {}
        return _text_response(json.dumps(payload, ensure_ascii=False, indent=2))
    return _text_response(r2(f"pdf @ {addr}"))


def pd_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    addr = _query_str(params, "addr", required=True)
    count = _query_int(params, "count", 32, minimum=1, maximum=4096)
    fmt = _query_str(params, "fmt", "text") or "text"
    if fmt not in {"text", "json"}:
        raise ApiError(400, "fmt must be text or json")
    if fmt == "json":
        ops = r2j(f"pdj {count} @ {addr}") or []
        return _json_response({"addr": addr, "count": count, "ops": ops})
    return _text_response(r2(f"pdq {count} @ {addr}"))


def list_strings_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    offset = _query_int(params, "offset", 0, minimum=0)
    limit = _query_int(params, "limit", 100, minimum=1, maximum=1000)
    contains = _query_str(params, "contains", required=False)
    min_length = _query_int(params, "min_length", 0, minimum=0)
    strings = r2j("izj") or []
    items: List[Dict[str, Any]] = []
    for entry in strings:
        text = entry.get("string", "")
        if contains and contains not in text:
            continue
        if min_length and len(text) < min_length:
            continue
        items.append(
            {
                "addr": hex(entry.get("vaddr", 0) or entry.get("paddr", 0) or 0),
                "length": entry.get("length", 0),
                "type": entry.get("type"),
                "string": text,
            }
        )
    return _json_response(paginate(items, offset, limit))


def list_segments_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    offset = _query_int(params, "offset", 0, minimum=0)
    limit = _query_int(params, "limit", 100, minimum=1, maximum=1000)
    segs = r2j("iSj") or []
    mapped = [
        {
            "name": seg.get("name"),
            "vaddr": hex(seg.get("vaddr", 0)),
            "paddr": hex(seg.get("paddr", 0)),
            "size": seg.get("vsize", 0) or seg.get("size", 0),
            "perm": seg.get("perm"),
        }
        for seg in segs
    ]
    return _json_response(paginate(mapped, offset, limit))


def read_bytes_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    addr = _query_str(params, "addr", required=True)
    size = _query_int(params, "size", 64, minimum=1, maximum=65536)
    data = r2j(f"pxj {size} @ {addr}") or []
    return _json_response({"addr": addr, "size": size, "bytes": data})


def list_vars_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    addr = _query_str(params, "addr", required=True)
    try:
        varsj = r2j(f"afvlj @ {addr}")
    except ApiError:
        varsj = None

    out = {"reg": [], "stack": [], "args": [], "bpvars": []}
    if isinstance(varsj, dict):
        for key in ("reg", "regs", "args", "bpvars", "stack", "vars", "locals"):
            value = varsj.get(key)
            if not isinstance(value, list):
                continue
            if key in {"reg", "regs"}:
                out["reg"] = value
            elif key in {"vars", "locals", "stack"}:
                out["stack"] = value
            else:
                out[key] = value
    return _json_response({"addr": addr, "vars": out})


def set_comment_endpoint(body: Dict[str, Any]) -> Tuple[int, str, bytes]:
    addr = _body_str(body, "addr")
    text = _body_str(body, "text")
    r2(f"CCu {json.dumps(text)} @ {addr}")
    return _json_response({"ok": True})


def current_address_endpoint(_: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    value = r2("s").strip()
    try:
        addr = hex(int(value, 16))
    except Exception:
        addr = value if value.startswith("0x") else value
    return _json_response({"addr": addr})


def current_function_endpoint(_: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    info = r2j("afij @ $$") or []
    info0 = info[0] if isinstance(info, list) and info else {}
    return _json_response({"info": info0})


def xrefs_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    addr = _query_str(params, "addr", required=True)
    refs = r2j(f"axtj @ {addr}") or []
    return _json_response({"addr": addr, "xrefs": refs})


def list_globals_endpoint(params: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    offset = _query_int(params, "offset", 0, minimum=0)
    limit = _query_int(params, "limit", 100, minimum=1, maximum=1000)
    name_contains = _query_str(params, "name_contains", required=False)
    typ = _query_str(params, "typ", required=False)
    syms = r2j("isj") or []
    items: List[Dict[str, Any]] = []
    for sym in syms:
        item = {
            "name": sym.get("name"),
            "addr": hex(sym.get("vaddr", 0)),
            "paddr": hex(sym.get("paddr", 0)),
            "size": sym.get("size", 0),
            "bind": sym.get("bind"),
            "type": sym.get("type"),
        }
        if name_contains and name_contains not in (item["name"] or ""):
            continue
        if typ and (item["type"] or "").upper() != typ.upper():
            continue
        items.append(item)
    return _json_response(paginate(items, offset, limit))


def entrypoints_endpoint(_: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    try:
        entries = r2j("iej")
    except ApiError:
        entries = None
    return _json_response({"entries": entries or []})


def _with_seek(addr: str, callback) -> Any:
    current = r2("s").strip()
    try:
        r2(f"s {addr}")
        return callback()
    finally:
        if current:
            r2(f"s {current}")


def rename_local_variable_endpoint(body: Dict[str, Any]) -> Tuple[int, str, bytes]:
    func_addr = _body_str(body, "func_addr")
    old_name = _body_str(body, "old_name")
    new_name = _body_str(body, "new_name")

    def _rename() -> None:
        r2(f"afvn {new_name} {old_name}")

    _with_seek(func_addr, _rename)
    return _json_response({"ok": True})


def set_local_variable_type_endpoint(body: Dict[str, Any]) -> Tuple[int, str, bytes]:
    func_addr = _body_str(body, "func_addr")
    var_name = _body_str(body, "var_name")
    new_type = _body_str(body, "new_type")

    def _set_type() -> None:
        r2(f"afvt {var_name} {new_type}")

    _with_seek(func_addr, _set_type)
    return _json_response({"ok": True})


def list_types_endpoint(_: Dict[str, List[str]]) -> Tuple[int, str, bytes]:
    try:
        types = r2j("tj")
    except ApiError:
        types = None
    return _json_response({"types": types or []})


def set_function_prototype_endpoint(body: Dict[str, Any]) -> Tuple[int, str, bytes]:
    addr = _body_str(body, "addr")
    prototype = _body_str(body, "prototype")
    r2(f"afs {addr} {json.dumps(prototype)}")
    return _json_response({"ok": True})


def docs_endpoint() -> Tuple[int, str, bytes]:
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Cutter MCP Plugin API</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem auto; max-width: 900px; line-height: 1.5; }}
    code {{ background: #f3f3f3; padding: 0.1rem 0.3rem; border-radius: 4px; }}
    li {{ margin: 0.3rem 0; }}
  </style>
</head>
<body>
  <h1>Cutter MCP Plugin API</h1>
  <p>Version {PLUGIN_VERSION}. This server intentionally uses only Python stdlib so it can run inside Cutter's embedded Python on Windows.</p>
  <h2>GET</h2>
  <ul>
    <li><code>/api/v1/health</code></li>
    <li><code>/api/v1/functions</code></li>
    <li><code>/api/v1/functions/detail?addr=0x...</code></li>
    <li><code>/api/v1/decompile?addr=0x...</code></li>
    <li><code>/api/v1/disasm?addr=0x...&amp;fmt=text|json</code></li>
    <li><code>/api/v1/pd?addr=0x...&amp;count=32&amp;fmt=text|json</code></li>
    <li><code>/api/v1/strings</code></li>
    <li><code>/api/v1/segments</code></li>
    <li><code>/api/v1/bytes?addr=0x...&amp;size=64</code></li>
    <li><code>/api/v1/vars?addr=0x...</code></li>
    <li><code>/api/v1/current/address</code></li>
    <li><code>/api/v1/current/function</code></li>
    <li><code>/api/v1/xrefs?addr=0x...</code></li>
    <li><code>/api/v1/globals</code></li>
    <li><code>/api/v1/entrypoints</code></li>
    <li><code>/api/v1/types</code></li>
  </ul>
  <h2>POST</h2>
  <ul>
    <li><code>/api/v1/functions/rename</code></li>
    <li><code>/api/v1/comments</code></li>
    <li><code>/api/v1/vars/rename</code></li>
    <li><code>/api/v1/vars/set_type</code></li>
    <li><code>/api/v1/functions/set_prototype</code></li>
  </ul>
</body>
</html>
"""
    return _html_response(html)


GET_ROUTES = {
    "/api/v1/health": health_endpoint,
    "/api/v1/functions": list_functions_endpoint,
    "/api/v1/functions/detail": function_detail_endpoint,
    "/api/v1/decompile": decompile_endpoint,
    "/api/v1/disasm": disasm_endpoint,
    "/api/v1/pd": pd_endpoint,
    "/api/v1/strings": list_strings_endpoint,
    "/api/v1/segments": list_segments_endpoint,
    "/api/v1/bytes": read_bytes_endpoint,
    "/api/v1/vars": list_vars_endpoint,
    "/api/v1/current/address": current_address_endpoint,
    "/api/v1/current/function": current_function_endpoint,
    "/api/v1/xrefs": xrefs_endpoint,
    "/api/v1/globals": list_globals_endpoint,
    "/api/v1/entrypoints": entrypoints_endpoint,
    "/api/v1/types": list_types_endpoint,
}

POST_ROUTES = {
    "/api/v1/functions/rename": rename_function_endpoint,
    "/api/v1/comments": set_comment_endpoint,
    "/api/v1/vars/rename": rename_local_variable_endpoint,
    "/api/v1/vars/set_type": set_local_variable_type_endpoint,
    "/api/v1/functions/set_prototype": set_function_prototype_endpoint,
}


class CutterAPIRequestHandler(BaseHTTPRequestHandler):
    server_version = f"CutterMCP/{PLUGIN_VERSION}"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def _handle(self, method: str) -> None:
        try:
            parsed = urlparse(self.path)
            path = _normalize_path(parsed.path)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if method == "GET" and path == "/docs":
                status_code, content_type, payload = docs_endpoint()
            elif method == "GET":
                handler = GET_ROUTES.get(path)
                if handler is None:
                    raise ApiError(404, f"unknown path: {path}")
                status_code, content_type, payload = handler(params)
            else:
                handler = POST_ROUTES.get(path)
                if handler is None:
                    raise ApiError(404, f"unknown path: {path}")
                body = self._read_json_body()
                status_code, content_type, payload = handler(body)
        except ApiError as exc:
            status_code, content_type, payload = _json_response({"detail": exc.detail}, exc.status_code)
        except Exception as exc:
            status_code, content_type, payload = _json_response({"detail": str(exc)}, 500)

        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_body(self) -> Dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError:
            raise ApiError(400, "invalid Content-Length")
        if length > _MAX_BODY_BYTES:
            raise ApiError(413, "request body too large")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            body = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ApiError(400, f"invalid JSON body: {exc.msg}")
        if not isinstance(body, dict):
            raise ApiError(400, "JSON body must be an object")
        return body


class CutterHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class PluginHTTPThread(threading.Thread):
    def __init__(self, host: str, port: int):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self._server = None
        self._started_evt = threading.Event()
        self._start_error = ""

    def run(self) -> None:
        try:
            self._server = CutterHTTPServer((self.host, self.port), CutterAPIRequestHandler)
        except OSError as exc:
            self._start_error = str(exc)
            self._started_evt.set()
            return

        self._started_evt.set()
        try:
            self._server.serve_forever(poll_interval=0.2)
        finally:
            self._server.server_close()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()

    def wait_started(self, timeout: float = 5.0) -> bool:
        self._started_evt.wait(timeout)
        return not self._start_error and self._server is not None

    @property
    def start_error(self) -> str:
        return self._start_error


class MCPDockWidget(cutter.CutterDockWidget):
    def __init__(self, parent, action):
        super().__init__(parent, action)
        self.setObjectName("CutterMCPDock")
        self.setWindowTitle("MCP")

        self._thread = None
        self._status = QLabel("Stopped")
        self._host_input = QLineEdit("127.0.0.1")
        self._port_input = QSpinBox()
        self._port_input.setRange(1000, 65535)
        self._port_input.setValue(8000)
        self._open_docs_chk = QCheckBox("Open API docs on startup")
        self._open_docs_chk.setChecked(False)

        start_btn = QPushButton("Start Server")
        stop_btn = QPushButton("Stop Server")
        health_btn = QPushButton("Health Check")

        start_btn.clicked.connect(self.start_server)
        stop_btn.clicked.connect(self.stop_server)
        health_btn.clicked.connect(self.check_health)

        root = QWidget(self)
        self.setWidget(root)

        layout = QVBoxLayout(root)
        layout.addWidget(QLabel("Host:"))
        layout.addWidget(self._host_input)

        row = QHBoxLayout()
        row.addWidget(QLabel("Port:"))
        row.addWidget(self._port_input)
        layout.addLayout(row)

        layout.addWidget(self._open_docs_chk)
        layout.addWidget(start_btn)
        layout.addWidget(stop_btn)
        layout.addWidget(health_btn)
        layout.addWidget(QLabel("Status:"))
        layout.addWidget(self._status)
        layout.addStretch(1)

        QObject.connect(cutter.core(), SIGNAL("seekChanged(RVA)"), self.on_seek_changed)

    def on_seek_changed(self) -> None:
        try:
            current = cutter.cmd("s").strip()
            self._status.setText(f"{self.server_state()}  |  Current Address: {current}")
        except Exception:
            pass

    def server_state(self) -> str:
        return "🟢 Running" if self._thread and self._thread.is_alive() else "🔴 Stopped"

    def start_server(self) -> None:
        if self._thread and self._thread.is_alive():
            self._status.setText("🟢 Already running")
            return

        host = self._host_input.text().strip() or "127.0.0.1"
        port = int(self._port_input.value())
        self._thread = PluginHTTPThread(host, port)
        self._thread.start()

        ok = self._thread.wait_started(5.0)
        if ok:
            self._status.setText(f"🟢 Running | http://{host}:{port}/docs")
            if self._open_docs_chk.isChecked() and host == "127.0.0.1":
                webbrowser.open(f"http://127.0.0.1:{port}/docs")
            return

        detail = self._thread.start_error or "startup timeout"
        self._status.setText(f"🔴 Failed: {detail}")
        self._thread = None

    def stop_server(self) -> None:
        if not self._thread:
            self._status.setText("🔴 Stopped")
            return

        thread = self._thread
        thread.stop()
        thread.join(timeout=2.0)
        self._thread = None
        self._status.setText("🔴 Stopped")

    def check_health(self) -> None:
        host = self._host_input.text().strip() or "127.0.0.1"
        port = int(self._port_input.value())
        try:
            with socket.create_connection((host, port), timeout=0.5):
                ok = True
        except OSError:
            ok = False
        if ok:
            self._status.setText(f"{self.server_state()} | http://{host}:{port}/api/v1/health available")
        else:
            self._status.setText(f"{self.server_state()} | Port not open")

    def closeEvent(self, event) -> None:
        super().closeEvent(event)

    def shutdown(self) -> None:
        self.stop_server()


class CutterMCPPlugin(cutter.CutterPlugin):
    name = "CutterMCP+"
    description = "Expose Cutter/rizin info via a local HTTP server for MCP"
    version = PLUGIN_VERSION
    author = "restkhz"

    def setupPlugin(self) -> None:
        self._widget = None

    def setupInterface(self, main) -> None:
        action = QAction("Cutter MCP Server", main)
        action.setCheckable(True)
        self._widget = MCPDockWidget(main, action)
        main.addPluginDockWidget(self._widget, action)

    def terminate(self) -> None:
        if self._widget:
            self._widget.shutdown()
            self._widget = None


def create_cutter_plugin():
    return CutterMCPPlugin()
