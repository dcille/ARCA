"""GCP CIS Evaluator Engine — Orchestrates evaluation of all 69 CIS GCP v4.0 controls."""

import json
import logging
import time
from typing import Optional

from .evaluators.base import GCPClientCache, EvalConfig, make_manual_result, safe_evaluate
from .evaluators import EVALUATOR_REGISTRY, get_evaluator

logger = logging.getLogger(__name__)


class GCPCISEvaluatorEngine:
    def __init__(self, credentials: dict, services=None, regions=None):
        self.credentials = credentials
        self.project_id = credentials.get("project_id", "")
        self.services = services
        self.regions = regions or ["us-central1"]
        self._clients = None
        self._config = None
        self._cis_controls = None

    def _get_credentials(self):
        from google.oauth2 import service_account
        cred_info = self.credentials.get("service_account_key")
        if isinstance(cred_info, str):
            cred_info = json.loads(cred_info)
        return service_account.Credentials.from_service_account_info(cred_info)

    def _get_clients(self):
        if not self._clients:
            self._clients = GCPClientCache(self._get_credentials(), self.project_id)
        return self._clients

    def _get_config(self):
        if not self._config:
            self._config = EvalConfig(project_id=self.project_id, regions=self.regions)
        return self._config

    def _get_cis_controls(self):
        if not self._cis_controls:
            from scanner.cis_controls.gcp_cis_controls import GCP_CIS_CONTROLS
            self._cis_controls = GCP_CIS_CONTROLS
        return self._cis_controls

    _SECTION_MAP = {"1":"iam","2":"logging","3":"networking","4":"compute","5":"storage","6":"sql","7":"bigquery","8":"dataproc"}

    def evaluate_all(self):
        controls = self._get_cis_controls()
        clients, config = self._get_clients(), self._get_config()
        all_results, evaluated, manual = [], 0, 0
        start = time.monotonic()
        logger.info("Starting GCP CIS evaluation: %d controls, %d evaluators", len(controls), len(EVALUATOR_REGISTRY))

        for ctrl in controls:
            cid = ctrl["cis_id"]
            if self.services:
                sec = cid.split(".")[0]
                if self._SECTION_MAP.get(sec,"") not in self.services:
                    continue
            ev = get_evaluator(cid)
            if ev:
                results = safe_evaluate(ev, clients, config, cid, f"gcp_cis_{cid.replace('.','_')}", ctrl["title"], ctrl.get("service_area","general"), ctrl["severity"])
                all_results.extend(results)
                evaluated += 1
            else:
                all_results.append(make_manual_result(cid, f"gcp_cis_{cid.replace('.','_')}", ctrl["title"], ctrl.get("service_area","general"), ctrl["severity"], config.project_id, f"Evaluator not in registry for {cid}."))
                manual += 1

        logger.info("GCP CIS: %d evaluated, %d manual in %.1fs. Total: %d results", evaluated, manual, time.monotonic()-start, len(all_results))
        return all_results

    def evaluate_single(self, cis_id):
        ctrl = next((c for c in self._get_cis_controls() if c["cis_id"]==cis_id), None)
        if not ctrl: return [{"error": f"Control {cis_id} not found"}]
        ev = get_evaluator(cis_id)
        if not ev: return [make_manual_result(cis_id, f"gcp_cis_{cis_id.replace('.','_')}", ctrl["title"], ctrl.get("service_area","general"), ctrl["severity"], self.project_id, "No evaluator.")]
        return safe_evaluate(ev, self._get_clients(), self._get_config(), cis_id, f"gcp_cis_{cis_id.replace('.','_')}", ctrl["title"], ctrl.get("service_area","general"), ctrl["severity"])

    def coverage_report(self):
        controls = self._get_cis_controls()
        impl = sum(1 for c in controls if get_evaluator(c["cis_id"]))
        return {"benchmark":"CIS Google Cloud Platform Foundation v4.0.0","total":len(controls),"implemented":impl,"coverage_pct":round(impl/len(controls)*100,1)}
