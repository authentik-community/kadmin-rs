from kadmin._lib import sys  # type: ignore[import-not-found]

__all__ = []

if hasattr(sys, "mit_client"):
    mit_client = sys.mit_client
    __all__.append("mit_client")
if hasattr(sys, "mit_server"):
    mit_server = sys.mit_server
    __all__.append("mit_server")
if hasattr(sys, "heimdal_client"):
    heimdal_client = sys.heimdal_client
    __all__.append("heimdal_client")
if hasattr(sys, "heimdal_server"):
    heimdal_server = sys.heimdal_server
    __all__.append("heimdal_server")

__all__ = tuple(__all__)
