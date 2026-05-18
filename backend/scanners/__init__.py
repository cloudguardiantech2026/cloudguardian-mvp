from backend.scanners.azure import (
    azure_ce1_firewall,
    azure_ce2_secure_config,
    azure_ce3_access_control,
    azure_ce4_malware,
    azure_ce5_patching,
)

def run_azure_scan():
    results = []
    for module in [
        azure_ce1_firewall,
        azure_ce2_secure_config,
        azure_ce3_access_control,
        azure_ce4_malware,
        azure_ce5_patching,
    ]:
        try:
            results.extend(module.scan())
        except Exception as e:
            results.append({
                "provider": "azure",
                "control": module.__name__,
                "resource": "scanner",
                "status": "ERROR",
                "detail": str(e),
            })
    return results
