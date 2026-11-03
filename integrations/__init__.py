"""Unified free-API integration layer.

    from integrations import manager
    manager.statuses()                       # every provider's status (no network)
    manager.test("abuseipdb")                # one live connection test
    manager.lookup("gdelt", "query", "...")  # normalized result, never raises

See integrations/base.py for the adapter contract and API_PROVIDER_REFERENCE.md for each provider.
"""
