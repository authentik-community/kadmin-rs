# https://www.sphinx-doc.org/en/master/usage/configuration.html

project = "python-kadmin-rs"
copyright = "authentik community"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx_rtd_theme",
]
exclude_patterns = ["_build"]

html_theme = "sphinx_rtd_theme"
