# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje guardrail helper — inlined once per file (see _import_hint); no
# separate package to install. gr_check() POSTs to GR_SERVICE_URL + "/enforce"
# and fails open (returns `data` unchanged) unless a policy deliberately
# blocks it (GRBlockedError, only on GR_BLOCK_MODE=enforce + an HTTP 403).
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id = policy_id
        self.reason = reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))


def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _lineaje_json
    import logging as _lineaje_logging
    import os as _lineaje_os
    import urllib.error as _lineaje_urlerr
    import urllib.request as _lineaje_urlreq
    _logger = _lineaje_logging.getLogger("lineaje.gr_client")
    url = _lineaje_os.environ.get("GR_SERVICE_URL", "")  # Lineaje: guardrail endpoint
    if not url:
        return data  # Lineaje: fail-open — GR_SERVICE_URL not configured
    tid = tenant_id or _lineaje_os.environ.get("GR_TENANT_ID", "")
    bearer = _lineaje_os.environ.get("GR_BEARER_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {
            "source_type": source_type,
            "destination_type": destination_type,
            params_key: {"data": data},
        }
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _lineaje_urlreq.Request(
            url.rstrip("/") + "/enforce",
            data=_lineaje_json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        with _lineaje_urlreq.urlopen(req, timeout=timeout) as resp:
            result = _lineaje_json.loads(resp.read())
    except _lineaje_urlerr.HTTPError as exc:
        if exc.code == 403:
            try:
                detail = _lineaje_json.loads(exc.read()).get("detail", {})
            except Exception:
                detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _logger.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _lineaje_os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    except Exception as exc:
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _logger.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _lineaje_sys, os as _lineaje_os, importlib.util as _lineaje_ilu
    if "_lineaje_gr_stub_client" in _lineaje_sys.modules:
        return _lineaje_sys.modules["_lineaje_gr_stub_client"]
    _here = _lineaje_os.path.dirname(_lineaje_os.path.abspath(__file__))
    _cur, _path = _here, _lineaje_os.path.join(_here, "gr_stub_client.py")
    for _ in range(8):
        _cand = _lineaje_os.path.join(_cur, "gr_stub_client.py")
        if _lineaje_os.path.isfile(_cand):
            _path = _cand
            break
        _parent = _lineaje_os.path.dirname(_cur)
        if _parent == _cur:
            break
        _cur = _parent
    _spec = _lineaje_ilu.spec_from_file_location("_lineaje_gr_stub_client", _path)
    _mod = _lineaje_ilu.module_from_spec(_spec)
    _lineaje_sys.modules["_lineaje_gr_stub_client"] = _mod
    _spec.loader.exec_module(_mod)
    try:
        _mod = gr_check(_mod, "agent", "user_interface", site_id='site:sha256:70393d60aca77ff6b63ede595f58666659214c52ac020f1dbec504d67ff30dd1')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _mod = _mod
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return _mod
from flask import Flask, render_template, request, jsonify, session
import openai
import base64
import os
import requests
from dotenv import load_dotenv
from quivr_core import Brain
from quivr_core.rag.entities.config import RetrievalConfig
from tempfile import NamedTemporaryFile
from werkzeug.utils import secure_filename
from asyncio import to_thread
import asyncio


UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "secret"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["CACHE_TYPE"] = "SimpleCache"  # In-memory cache for development
app.config["CACHE_DEFAULT_TIMEOUT"] = 60 * 60  # 1 hour cache timeout
load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")

brains = {}


@app.route("/")
def index():
    _lineaje_payload_57 = "index.html"
    try:
        _lineaje_payload_57 = gr_check(_lineaje_payload_57, "tool", "user_interface", site_id='site:sha256:18bf20fc401de42f1a26ebc99253024d153cb0334ae5b1d4c904de9da96da05b')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload_57 = _lineaje_payload_57
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'tool->user_interface' — passing data through unchecked"
        )
    return render_template("index.html")


def run_in_event_loop(func, *args, **kwargs):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    if asyncio.iscoroutinefunction(func):
        result = loop.run_until_complete(func(*args, **kwargs))
    else:
        result = func(*args, **kwargs)
    loop.close()
    try:
        result = gr_check(result, "agent", "user_interface", site_id='site:sha256:ffcbc0cc7116dfd3069669ce4b02abc06e13efebed2eef28bb263a3fa6709777')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        result = result
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return result


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
async def upload_file():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]

    if file.filename == "":
        return "No selected file", 400
    if not (file and file.filename and allowed_file(file.filename)):
        return "Invalid file type", 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    _lineaje_payload_91 = f"File uploaded and saved at: {filepath}"
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload_91 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_91, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload_91 = _lineaje_payload_91
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
        )
    print(f"File uploaded and saved at: {filepath}")

    _lineaje_payload_93 = "Creating brain instance..."
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload_93 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_93, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload_93 = _lineaje_payload_93
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
        )
    print("Creating brain instance...")

    brain: Brain = await to_thread(
        run_in_event_loop, Brain.from_files, name="user_brain", file_paths=[filepath]
    )

    # Store brain instance in cache
    session_id = session.sid if hasattr(session, "sid") else os.urandom(16).hex()
    session["session_id"] = session_id
    # cache.set(session_id, brain)  # Store the brain instance in the cache
    brains[session_id] = brain
    _lineaje_payload_104 = f"Brain instance created and stored in cache for session ID: {session_id}"
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload_104 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_104, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload_104 = _lineaje_payload_104
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
        )
    print(f"Brain instance created and stored in cache for session ID: {session_id}")

    _lineaje_payload_106 = {"message": "Brain created successfully"}
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload_106 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_106, "agent", "user_interface", site_id='site:sha256:7467efaf379c851ac52761b8eb98d9f5f8f584782411e28625360ea59f1917ad')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload_106 = _lineaje_payload_106
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return jsonify({"message": "Brain created successfully"})


@app.route("/ask", methods=["POST"])
async def ask():
    if "audio_data" not in request.files:
        return "Missing audio data", 400

    # Retrieve the brain instance from the cache using the session ID
    session_id = session.get("session_id")
    if not session_id:
        return "Session ID not found. Upload a file first.", 400

    brain = brains.get(session_id)
    if not brain:
        return "Brain instance not found in dict. Upload a file first.", 400

    _lineaje_payload_123 = "Brain instance loaded from cache."
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload_123 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_123, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload_123 = _lineaje_payload_123
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
        )
    print("Brain instance loaded from cache.")

    _lineaje_payload_125 = "Speech to text..."
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload_125 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_125, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload_125 = _lineaje_payload_125
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
        )
    print("Speech to text...")
    audio_file = request.files["audio_data"]
    transcript = transcribe_audio_file(audio_file)
    try:
        import asyncio as _gr_asyncio
        transcript = await _gr_asyncio.to_thread(gr_check, transcript, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        transcript = transcript
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
        )
    print("Transcript result: ", transcript)

    _lineaje_payload = "Getting response..."
    # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_VULN_SEC_007 (AI systems must implement incident detection, structured logging, and reporting mechanisms). Mask/block; do not remove without review. site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload = _lineaje_payload
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
        )
    print(_lineaje_payload)
    quivr_response = await to_thread(run_in_event_loop, brain.ask, transcript)

    _lineaje_payload_138 = "Text to speech..."
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload_138 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_138, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload_138 = _lineaje_payload_138
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
        )
    print("Text to speech...")
    audio_base64 = synthesize_speech(quivr_response.answer)

    _lineaje_payload_141 = "Done"
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload_141 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_141, "agent", "log", site_id='site:sha256:e4b5b8f0a47e56169b0697dc231075350ebd17cad0545da6936da16622911761')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload_141 = _lineaje_payload_141
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
        )
    print("Done")
    _lineaje_payload = {"audio_base64": audio_base64}
    # LINEAJE: enforce() `_lineaje_payload` at agent->user_interface data_egress — scan flagged AI_IAC_023 (Chatbot and AI interfaces must disclose AI identity to the user). Mask/block; do not remove without review. site_id='site:sha256:7467efaf379c851ac52761b8eb98d9f5f8f584782411e28625360ea59f1917ad'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7467efaf379c851ac52761b8eb98d9f5f8f584782411e28625360ea59f1917ad', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='text/plain'))
    try:
        import asyncio as _gr_asyncio
        _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "user_interface", site_id='site:sha256:7467efaf379c851ac52761b8eb98d9f5f8f584782411e28625360ea59f1917ad')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _lineaje_payload = _lineaje_payload
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return jsonify(_lineaje_payload)


def transcribe_audio_file(audio_file):
    with NamedTemporaryFile(suffix=".webm", delete=False) as temp_audio_file:
        audio_file.save(temp_audio_file)
        temp_audio_file_path = temp_audio_file.name

    try:
        with open(temp_audio_file_path, "rb") as f:
            transcript_response = openai.audio.transcriptions.create(
                model="whisper-1", file=f
            )
        transcript = transcript_response.text
    finally:
        # LINEAJE: enforce() `temp_audio_file_path` at agent->system security_decision — scan flagged AI_APP_SEC_069 (AI Agent must implement Human-in-the-Loop (HITL) approval flow for risky operations like delete, purge, destroy). Mask/block; do not remove without review. site_id='site:sha256:0d83b71901cb8fa94db9955de9d711bd8f6cc102c4e0cc055fe2e4c7796575d2'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0d83b71901cb8fa94db9955de9d711bd8f6cc102c4e0cc055fe2e4c7796575d2', phase='security_decision', boundary={'source': 'agent_message', 'sink': 'agent_message'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='system')
        temp_audio_file_path = _gr_client.enforce(_gr_site, temp_audio_file_path, content_type='application/json', variable_name='temp_audio_file_path', source_file=__file__, before_line=163)
        os.unlink(temp_audio_file_path)

    try:
        transcript = gr_check(transcript, "agent", "user_interface", site_id='site:sha256:45d3f7815a6db56c52bfb948a2a4b8b25a763e9f475f49d8e92bd33bc52600b6')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        transcript = transcript
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return transcript


def synthesize_speech(text):
    speech_response = openai.audio.speech.create(
        model="tts-1", voice="nova", input=text
    )
    audio_content = speech_response.content
    audio_base64 = base64.b64encode(audio_content).decode("utf-8")
    try:
        audio_base64 = gr_check(audio_base64, "agent", "user_interface", site_id='site:sha256:a9c6367d4a467e0baab232b2cad6d3af14b1edb1e01b63fe4f12c646492c79a2')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        audio_base64 = audio_base64
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return audio_base64


if __name__ == "__main__":
    app.run(debug=True)
