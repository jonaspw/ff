# backend/analyzer/config.py

import json
import os
from django.conf import settings


CONFIG_PATH = os.path.join(settings.BASE_DIR, "scoring_config.json")

DEFAULT_CONFIG = {
    "weights": {
        "virustotal": 20,
        "abuseipdb":  20,
        "threatfox":  20,
        "circl":      20,
        "shodan":     20,
    },
    "enabled": {
        "virustotal": True,
        "abuseipdb":  True,
        "threatfox":  True,
        "circl":      True,
        "shodan":     True,
    }
}


def load_config() -> dict:
    """
    Wczytuje konfigurację z pliku JSON.
    """
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG.copy()


def save_config(weights: dict, enabled: dict) -> dict:
    """
    Zapisuje konfigurację do pliku JSON.
    """
    # Walidacja
    active_sum = sum(
        w for source, w in weights.items()
        if enabled.get(source, True)
    )
    if active_sum != 100:
        raise ValueError(
            f"The sum of the active source weights must be 100% "
            f"(currently: {active_sum}%)"
        )

    config = {"weights": weights, "enabled": enabled}

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    return config


def get_effective_weights() -> dict:
    """
    Zwraca efektywne wagi — wyłączone źródła mają wagę 0.
    """
    config  = load_config()
    weights = config.get("weights", DEFAULT_CONFIG["weights"])
    enabled = config.get("enabled", DEFAULT_CONFIG["enabled"])

    return {
        source: (w if enabled.get(source, True) else 0)
        for source, w in weights.items()
    }
