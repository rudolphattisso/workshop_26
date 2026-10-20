"""Socle commun des services Python de RESILIENCE-ALPHA.

Usage minimal dans un service :

    from resilience_common import create_app

    app = create_app("payment-api", ready_checks={"database": ping_db})
"""

from resilience_common.app import create_app

__all__ = ["create_app"]
