# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_gr_load(_f):
    """Lineaje-added: load gr_stub_client.py beside _f or in one of its 7 parent folders. Missing or broken:
    a pass-through client and ONE warning per process (GR_REQUIRE_CLIENT=1: ImportError instead)."""
    import sys, os, logging, importlib.util as u, pathlib
    n = "_lineaje_gr_stub_client"
    if n in sys.modules: return sys.modules[n]
    h = pathlib.Path(_f or ".").resolve().parent
    d = [h, *h.parents][:8]
    p = next((x / "gr_stub_client.py" for x in d if (x / "gr_stub_client.py").is_file()), None)
    try:
        s = u.spec_from_file_location(n, p) if p else None
        if s is None: raise FileNotFoundError("gr_stub_client.py")
        m = sys.modules[n] = u.module_from_spec(s); s.loader.exec_module(m); return m
    except Exception as e:
        sys.modules.pop(n, None)
        w = ("gr_stub_client.py not found for %s (searched: %s)" % (_f or "<no __file__>", ", ".join(map(str, d)))
             if p is None else "%s failed to load (%s%s)" % (p, type(e).__name__,
                                                          " line %s" % e.lineno if isinstance(e, SyntaxError) else ""))
        w = ("Lineaje guardrail NOT active: " + w + ". Calls pass through unchecked; set GR_REQUIRE_CLIENT=1 to fail "
             "instead. Each deploy unit needs gr_stub_client.py beside its code and GR_SERVICE_URL plus credentials as "
             "environment variables.")
        if os.environ.get("GR_REQUIRE_CLIENT", "").strip() == "1": raise ImportError(w) from (None if p is None else e)
        z = sys.__dict__.setdefault("_lineaje_gr_null", __import__('types').SimpleNamespace(STUB_API=999999, GuardrailUnavailableError=type('GuardrailUnavailableError', (PermissionError,), {}), SiteDescriptor=lambda *a, **k: None, new_interaction_id=lambda *a, **k: None, enforce=lambda _s, _p, *a, **k: _p, enforce_request=lambda _s, _p, *a, **k: _p, enforce_reply=lambda _s, _p, *a, **k: _p, _lineaje_seen=set()))
        k = "missing" if p is None else (str(p), type(e).__name__)
        if k not in z._lineaje_seen:
            z._lineaje_seen.add(k); g = logging.getLogger("lineaje.guardrail"); g.log(30 if p is None else 40, w)
            if g.hasHandlers(): sys.stderr.write(w + "\n")
        return z
__import__("sys").__dict__.setdefault("_lineaje_gr_load_v1", _lineaje_gr_load)
del _lineaje_gr_load
def _lineaje_load_gr_client():
    """Lineaje-added: this file's gr_stub_client.py (the loader _lineaje_gr_load registered)."""
    return __import__("sys").__dict__["_lineaje_gr_load_v1"](globals().get("__file__"))
if __import__("os").environ.get("GR_REQUIRE_CLIENT", "").strip() == "1": __import__("sys").__dict__["_lineaje_gr_load_v1"](globals().get("__file__"))

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict
from typing import Self


class QuivrBaseConfig(BaseModel):
    """
    Base configuration class for Quivr.

    This class extends Pydantic's BaseModel and provides a foundation for
    configuration management in quivr-core.

    Attributes:
        model_config (ConfigDict): Configuration for the Pydantic model.
            It's set to forbid extra attributes, ensuring strict adherence
            to the defined schema.

    Class Methods:
        from_yaml: Create an instance of the class from a YAML file.
    """

    model_config = ConfigDict(extra="forbid")

    @classmethod
    def from_yaml(cls, file_path: str | Path) -> Self:
        """
        Create an instance of the class from a YAML file.

        Args:
            file_path (str | Path): The path to the YAML file.

        Returns:
            QuivrBaseConfig: An instance of the class initialized with the data from the YAML file.
        """
        # Load the YAML file
        with open(file_path, "r") as stream:
            # LINEAJE: runtime guardrail checks `stream` as it flows from file storage to the agent (in QuivrBaseConfig.from_yaml).
            #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: medium).
            #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `stream` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:80c7551551a072f8a13d828ff6f767641e97793bbc0a5ad59fcba82621de8975'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:80c7551551a072f8a13d828ff6f767641e97793bbc0a5ad59fcba82621de8975', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'invocation': {'file': 'core/quivr_core/base_config.py', 'line': 39, 'function': 'QuivrBaseConfig.from_yaml'}, 'file': 'core/quivr_core/base_config.py', 'line': 39, 'function': 'from_yaml', 'agent_name': 'QuivrBaseConfig', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                stream = _gr_client.enforce(_gr_site, stream, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            config_data = yaml.safe_load(stream)

        # Instantiate the class using the YAML data
        return cls(**config_data)
