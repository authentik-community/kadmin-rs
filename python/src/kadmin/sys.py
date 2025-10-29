from kadmin._lib import sys  # type: ignore[import-not-found]

__all__ = ()

if hasattr(sys, "mit_client"):
    mit_client = sys.mit_client
    __all__ = __all__ + ("mit_client",)
if hasattr(sys, "mit_server"):
    mit_server = sys.mit_server
    __all__ = __all__ + ("mit_server",)
if hasattr(sys, "heimdal_client"):
    heimdal_client = sys.heimdal_client
    __all__ = __all__ + ("heimdal_client",)
if hasattr(sys, "heimdal_server"):
    heimdal_server = sys.heimdal_server
    __all__ = __all__ + ("heimdal_server",)
