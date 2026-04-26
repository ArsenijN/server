import os

_SNIPPETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'snippets')

def _load_snippet(filename: str) -> str:
    """Load an HTML snippet from the snippets/ subfolder."""
    with open(os.path.join(_SNIPPETS_DIR, filename), encoding='utf-8') as f:
        return f.read()

def _render_snippet(filename: str, **kwargs) -> str:
    """Load a snippet and substitute {PLACEHOLDER} tokens safely.

    Unlike str.format(), this only replaces tokens whose names are explicitly
    passed as keyword arguments, so CSS rules like *{box-sizing:border-box}
    and JS template literals like ${previewUrl} are left completely untouched.
    """
    template = _load_snippet(filename)
    for key, value in kwargs.items():
        template = template.replace('{' + key + '}', str(value))
    return template