"""
The bundled GeoNames city list, now provided by the routemap package (v3.36.0).

The engine moved to https://github.com/osintph/routemap so the desktop app and
this tab share one implementation. This module IS that one: importing
``app.routemap.cities`` binds the name to ``routemap.engine.cities`` itself, not
to a copy, so every caller and every test that patches an attribute here is
patching the code that actually runs.
"""
import sys

from routemap.engine import cities as _engine

sys.modules[__name__] = _engine
