from lib.cuckoo.common.abstracts import Processing


class TriggerProfiler(Processing):
    order = 99

    def run(self):
        self.key = "trigger_profile"

        results = {
            "suspected": False,
            "primary": None,
            "scores": {
                "time": 0.0,
                "environment": 0.0,
                "user": 0.0,
            },
            "evidence": [],
        }

        signatures = self.results.get("signatures", []) or []
        behavior = self.results.get("behavior", {}) or {}
        summary = behavior.get("summary") or {}
        network = self.results.get("network", {}) or {}

        sig_names = {
            sig.get("name", "").lower()
            for sig in signatures
            if isinstance(sig, dict)
        }

        if any("antivm" in s or "antisandbox" in s for s in sig_names):
            results["scores"]["environment"] += 0.7
            results["evidence"].append("Anti-VM or anti-sandbox signature matched")

        if any("sleep" in s for s in sig_names):
            results["scores"]["time"] += 0.7
            results["evidence"].append("Sleep-related signature matched")

        if any("keyboard_layout" in s or "queries_keyboard_layout" in s for s in sig_names):
            results["scores"]["environment"] += 0.1
            results["evidence"].append("Keyboard layout queried")

        files = summary.get("files", []) if isinstance(summary, dict) else []
        has_network = bool(network)

        if not files and not has_network:
            results["scores"]["user"] += 0.2
            results["evidence"].append("Low baseline activity observed")

        primary = max(results["scores"], key=results["scores"].get)
        if results["scores"][primary] >= 0.5:
            results["suspected"] = True
            results["primary"] = primary

        return results
