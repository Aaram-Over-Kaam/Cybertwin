from __future__ import annotations

import os
import socket
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "cybertwin_model.pkl"
TEST_PATH = ROOT / "UNSW_NB15_testing-set.csv"

SEVERITY_WEIGHTS = {
    "Normal": 0.05,
    "Analysis": 0.45,
    "Reconnaissance": 0.55,
    "Fuzzers": 0.65,
    "DoS": 0.78,
    "Exploits": 0.86,
    "Backdoor": 0.9,
    "Generic": 0.82,
    "Shellcode": 0.96,
    "Worms": 1.0,
}

PLAYBOOK = {
    "Normal": "Keep the node under baseline monitoring and continue routine logging.",
    "Analysis": "Inspect reconnaissance traces, correlate with recent scans, and tighten telemetry collection.",
    "Reconnaissance": "Rate-limit probing sources, review firewall rules, and watch for follow-up exploitation attempts.",
    "Fuzzers": "Inspect malformed request spikes, add WAF rules, and isolate unstable services from production traffic.",
    "DoS": "Enable traffic filtering, autoscaling, and upstream rate controls before service degradation spreads.",
    "Exploits": "Patch exposed services, isolate the node, and check neighboring systems for lateral movement indicators.",
    "Backdoor": "Rotate credentials, isolate the host, and start containment plus forensic review immediately.",
    "Generic": "Escalate to IR triage, verify signatures against known attack kits, and inspect adjacent nodes.",
    "Shellcode": "Treat as critical execution risk, isolate the endpoint, and trigger memory and process forensics.",
    "Worms": "Sever lateral links, quarantine infected segments, and block automated propagation across the twin.",
}

MOCK_USERS = [
    {
        "user_id": "usr-1001",
        "name": "Aman Sharma",
        "role": "Security Analyst",
        "team": "Cyber Defense",
        "location": "SOC Bengaluru",
    },
    {
        "user_id": "usr-1002",
        "name": "Riya Verma",
        "role": "Network Engineer",
        "team": "InfraOps",
        "location": "SOC Pune",
    },
]

MOCK_NODES = [
    {
        "node_id": "CT-EDGE-01",
        "zone": "DMZ",
        "owner": "Payments",
        "status": "healthy",
        "latency_ms": 24,
        "traffic": "high",
        "risk_profile": "normal",
    },
    {
        "node_id": "CT-EDGE-07",
        "zone": "DMZ",
        "owner": "Public API",
        "status": "warning",
        "latency_ms": 49,
        "traffic": "spike",
        "risk_profile": "suspicious",
    },
    {
        "node_id": "CT-DB-03",
        "zone": "Core",
        "owner": "Identity",
        "status": "critical",
        "latency_ms": 83,
        "traffic": "burst",
        "risk_profile": "critical",
    },
    {
        "node_id": "CT-IOT-14",
        "zone": "Factory",
        "owner": "Manufacturing",
        "status": "healthy",
        "latency_ms": 34,
        "traffic": "normal",
        "risk_profile": "normal",
    },
    {
        "node_id": "CT-APP-12",
        "zone": "Core",
        "owner": "Customer Portal",
        "status": "warning",
        "latency_ms": 58,
        "traffic": "high",
        "risk_profile": "suspicious",
    },
]

MOCK_INCIDENTS = [
    {
        "incident_id": "INC-7712",
        "title": "Unusual UDP burst from edge gateway",
        "severity": "high",
        "status": "investigating",
        "node_id": "CT-EDGE-07",
    },
    {
        "incident_id": "INC-7716",
        "title": "Abnormal outbound session chaining",
        "severity": "medium",
        "status": "triaged",
        "node_id": "CT-APP-12",
    },
    {
        "incident_id": "INC-7721",
        "title": "Possible exploitation pattern in core DB tier",
        "severity": "critical",
        "status": "containment",
        "node_id": "CT-DB-03",
    },
]

MOCK_ACTIVITY = [
    "Policy sync completed for 18 twin segments",
    "Auto-isolation drill succeeded in staging",
    "SIEM ingestion latency normalized",
    "Threat intel feed updated with 213 indicators",
]

MOCK_SCENARIOS = [
    {
        "scenario_id": "SIM-201",
        "title": "Ransomware propagation through shared identity services",
        "attack_vector": "Credential abuse",
        "target_node": "CT-DB-03",
        "affected_nodes": ["CT-DB-03", "CT-APP-12"],
        "impact": "High blast radius across identity and citizen access flows",
        "readiness_score": 58,
        "status": "requires drill",
    },
    {
        "scenario_id": "SIM-204",
        "title": "Public API fuzzing against exposed edge workloads",
        "attack_vector": "Malformed request storm",
        "target_node": "CT-EDGE-07",
        "affected_nodes": ["CT-EDGE-07"],
        "impact": "Service instability in the DMZ with moderate downstream risk",
        "readiness_score": 71,
        "status": "monitoring",
    },
    {
        "scenario_id": "SIM-209",
        "title": "Lateral movement from IoT control segment",
        "attack_vector": "Compromised device pivot",
        "target_node": "CT-IOT-14",
        "affected_nodes": ["CT-IOT-14", "CT-APP-12"],
        "impact": "Operational technology bridge into core application space",
        "readiness_score": 64,
        "status": "needs validation",
    },
]


def safe_divide(numerator: pd.Series, denominator: pd.Series, fallback: float = 0.0) -> pd.Series:
    denominator = denominator.replace(0, np.nan)
    result = numerator / denominator
    return result.replace([np.inf, -np.inf], np.nan).fillna(fallback)


def engineer_features(frame: pd.DataFrame) -> pd.DataFrame:
    engineered = frame.copy()

    if {"spkts", "dpkts"}.issubset(engineered.columns):
        engineered["total_packets"] = engineered["spkts"] + engineered["dpkts"]
        engineered["packet_imbalance"] = safe_divide(
            (engineered["spkts"] - engineered["dpkts"]).abs(),
            engineered["total_packets"] + 1,
        )

    if {"sbytes", "dbytes"}.issubset(engineered.columns):
        engineered["total_bytes"] = engineered["sbytes"] + engineered["dbytes"]
        engineered["byte_imbalance"] = safe_divide(
            (engineered["sbytes"] - engineered["dbytes"]).abs(),
            engineered["total_bytes"] + 1,
        )

    if {"total_bytes", "total_packets"}.issubset(engineered.columns):
        engineered["bytes_per_packet"] = safe_divide(
            engineered["total_bytes"],
            engineered["total_packets"] + 1,
        )

    if {"sload", "dload"}.issubset(engineered.columns):
        engineered["load_ratio"] = safe_divide(engineered["sload"] + 1, engineered["dload"] + 1)
        engineered["load_gap"] = (engineered["sload"] - engineered["dload"]).abs()

    if {"sjit", "djit"}.issubset(engineered.columns):
        engineered["jitter_gap"] = (engineered["sjit"] - engineered["djit"]).abs()
        engineered["jitter_ratio"] = safe_divide(engineered["sjit"] + 1, engineered["djit"] + 1)

    if {"sttl", "dttl"}.issubset(engineered.columns):
        engineered["ttl_gap"] = (engineered["sttl"] - engineered["dttl"]).abs()

    if {"sinpkt", "dinpkt"}.issubset(engineered.columns):
        engineered["inter_packet_gap"] = (engineered["sinpkt"] - engineered["dinpkt"]).abs()

    if {"synack", "ackdat"}.issubset(engineered.columns):
        engineered["tcp_handshake_gap"] = (engineered["synack"] - engineered["ackdat"]).abs()

    if {"ct_srv_src", "ct_srv_dst"}.issubset(engineered.columns):
        engineered["service_fanout_gap"] = (engineered["ct_srv_src"] - engineered["ct_srv_dst"]).abs()

    if {"ct_dst_ltm", "ct_src_ltm"}.issubset(engineered.columns):
        engineered["lateral_movement_gap"] = (engineered["ct_dst_ltm"] - engineered["ct_src_ltm"]).abs()

    if {"rate", "dur"}.issubset(engineered.columns):
        engineered["rate_x_duration"] = engineered["rate"] * engineered["dur"]

    if "total_bytes" in engineered.columns:
        engineered["log_total_bytes"] = np.log1p(engineered["total_bytes"])

    if "rate" in engineered.columns:
        engineered["log_rate"] = np.log1p(engineered["rate"].clip(lower=0))

    return engineered


def normalize_scores(scores: np.ndarray, lower: float, upper: float) -> np.ndarray:
    spread = max(upper - lower, 1e-6)
    return np.clip((scores - lower) / spread, 0, 1)


def compute_risk_score(
    malicious_probability: np.ndarray,
    anomaly_probability: np.ndarray,
    predicted_attack: np.ndarray,
) -> np.ndarray:
    severity = np.array([SEVERITY_WEIGHTS.get(label, 0.6) for label in predicted_attack])
    return np.clip(
        0.62 * malicious_probability + 0.23 * anomaly_probability + 0.15 * severity,
        0,
        1,
    )


def blend_attack_predictions(
    binary_pred: np.ndarray,
    binary_prob: np.ndarray,
    attack_pred: np.ndarray,
    attack_prob: np.ndarray,
    normal_label: str,
) -> tuple[np.ndarray, np.ndarray]:
    final_attack_labels = np.where(binary_pred == 1, attack_pred, normal_label)
    final_attack_confidence = np.where(binary_pred == 1, attack_prob, 1 - binary_prob)
    return final_attack_labels, final_attack_confidence


class SinglePredictionRequest(BaseModel):
    record: dict[str, Any] = Field(..., description="One UNSW-NB15 style telemetry record.")


class BatchPredictionRequest(BaseModel):
    records: list[dict[str, Any]] = Field(..., description="A batch of telemetry records to score.")


class NodeBatchRequest(BaseModel):
    node_ids: list[str] = Field(..., description="Node identifiers to score with the trained ML model.")


class PredictionService:
    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model artifact not found at {model_path}. Run the training notebook to create cybertwin_model.pkl."
            )

        self.bundle = joblib.load(model_path)
        self.binary_pipeline = self.bundle["binary_pipeline"]
        self.attack_pipeline = self.bundle["attack_pipeline"]
        self.anomaly_pipeline = self.bundle["anomaly_pipeline"]
        self.input_columns = self.bundle["input_columns"]
        self.feature_columns = self.bundle["feature_columns"]
        self.input_schema = self.bundle["input_schema"]
        self.thresholds = self.bundle["thresholds"]
        self.normal_attack_label = self.bundle.get("normal_attack_label", "Normal")

    def _prepare_frame(self, records: list[dict[str, Any]]) -> pd.DataFrame:
        frame = pd.DataFrame(records)
        missing = [column for column in self.input_columns if column not in frame.columns]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        aligned = frame[self.input_columns].copy()
        engineered = engineer_features(aligned)
        return engineered[self.feature_columns]

    def _risk_band(self, score: float) -> str:
        if score >= self.thresholds["critical_risk"]:
            return "critical"
        if score >= self.thresholds["high_risk"]:
            return "high"
        if score >= self.thresholds["medium_risk"]:
            return "medium"
        return "low"

    def metadata(self) -> dict[str, Any]:
        return {
            "project_name": self.bundle["project_name"],
            "trained_at": self.bundle["trained_at"],
            "required_fields": self.input_columns,
            "input_schema": self.input_schema,
            "metrics": self.bundle.get("metrics", {}),
            "top_binary_features": self.bundle.get("top_binary_features", []),
            "top_attack_features": self.bundle.get("top_attack_features", []),
        }

    def predict(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        feature_frame = self._prepare_frame(records)

        malicious_prob = self.binary_pipeline.predict_proba(feature_frame)[:, 1]
        malicious_pred = self.binary_pipeline.predict(feature_frame)

        attack_pred = self.attack_pipeline.predict(feature_frame)
        attack_prob = self.attack_pipeline.predict_proba(feature_frame).max(axis=1)

        final_attack_pred, final_attack_confidence = blend_attack_predictions(
            binary_pred=malicious_pred,
            binary_prob=malicious_prob,
            attack_pred=attack_pred,
            attack_prob=attack_prob,
            normal_label=self.normal_attack_label,
        )

        anomaly_raw = -self.anomaly_pipeline.decision_function(feature_frame)
        anomaly_prob = normalize_scores(
            anomaly_raw,
            self.thresholds["anomaly_lower"],
            self.thresholds["anomaly_upper"],
        )

        risk_score = compute_risk_score(malicious_prob, anomaly_prob, final_attack_pred)

        results: list[dict[str, Any]] = []
        for index, raw_record in enumerate(records):
            predicted_attack = str(final_attack_pred[index])
            score = float(risk_score[index])
            malicious_probability = float(malicious_prob[index])
            anomaly_probability = float(anomaly_prob[index])
            attack_confidence = float(final_attack_confidence[index])

            results.append(
                {
                    "record_index": index,
                    "is_malicious": bool(malicious_pred[index]),
                    "predicted_attack": predicted_attack,
                    "binary_confidence": round(max(malicious_probability, 1 - malicious_probability), 4),
                    "malicious_probability": round(malicious_probability, 4),
                    "attack_confidence": round(attack_confidence, 4),
                    "anomaly_probability": round(anomaly_probability, 4),
                    "risk_score": round(score, 4),
                    "risk_band": self._risk_band(score),
                    "severity_weight": SEVERITY_WEIGHTS.get(predicted_attack, 0.6),
                    "recommended_action": PLAYBOOK.get(
                        predicted_attack,
                        "Investigate the node, review logs, and isolate it if the signal persists.",
                    ),
                    "record": raw_record,
                }
            )

        return results


def summarize_batch(predictions: list[dict[str, Any]]) -> dict[str, Any]:
    total_records = len(predictions)
    malicious_records = sum(1 for item in predictions if item["is_malicious"])
    average_risk_score = sum(item["risk_score"] for item in predictions) / max(total_records, 1)

    risk_breakdown: dict[str, int] = {}
    attack_breakdown: dict[str, int] = {}

    for item in predictions:
        risk_breakdown[item["risk_band"]] = risk_breakdown.get(item["risk_band"], 0) + 1
        attack_breakdown[item["predicted_attack"]] = attack_breakdown.get(item["predicted_attack"], 0) + 1

    top_attacks = dict(
        sorted(attack_breakdown.items(), key=lambda pair: pair[1], reverse=True)[:5]
    )

    return {
        "total_records": total_records,
        "malicious_records": malicious_records,
        "risk_breakdown": risk_breakdown,
        "top_attack_predictions": top_attacks,
        "average_risk_score": round(average_risk_score, 4),
    }


def profile_record(base_record: dict[str, Any], profile: str) -> dict[str, Any]:
    record = dict(base_record)

    if profile == "suspicious":
        if isinstance(record.get("rate"), (int, float)):
            record["rate"] = float(record["rate"]) * 1.25
        if isinstance(record.get("sload"), (int, float)):
            record["sload"] = float(record["sload"]) * 1.30
        if isinstance(record.get("spkts"), (int, float)):
            record["spkts"] = int(record["spkts"]) + 6

    if profile == "critical":
        if isinstance(record.get("rate"), (int, float)):
            record["rate"] = float(record["rate"]) * 1.70
        if isinstance(record.get("sload"), (int, float)):
            record["sload"] = float(record["sload"]) * 1.95
        if isinstance(record.get("spkts"), (int, float)):
            record["spkts"] = int(record["spkts"]) + 12
        if isinstance(record.get("ct_srv_dst"), (int, float)):
            record["ct_srv_dst"] = int(record["ct_srv_dst"]) + 3

    return record


def get_node_by_id(node_id: str) -> dict[str, Any]:
    for node in MOCK_NODES:
        if node["node_id"] == node_id:
            return node
    raise KeyError(node_id)


@lru_cache
def get_sample_record() -> dict[str, Any]:
    if not TEST_PATH.exists():
        raise FileNotFoundError(f"Testing dataset not found at {TEST_PATH}")

    frame = pd.read_csv(TEST_PATH)
    frame.columns = [str(column).replace("\ufeff", "").strip() for column in frame.columns]
    service = get_service()
    sample = frame.iloc[0][service.input_columns].to_dict()

    normalized: dict[str, Any] = {}
    for key, value in sample.items():
        if pd.isna(value):
            normalized[key] = None
        elif isinstance(value, np.generic):
            normalized[key] = value.item()
        else:
            normalized[key] = value
    return normalized


@lru_cache
def get_service() -> PredictionService:
    return PredictionService()


app = FastAPI(
    title="CyberTwin Inference API",
    version="1.0.0",
    description="Loads cybertwin_model.pkl and serves threat predictions for the frontend.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    service = get_service()
    return {
        "status": "ok",
        "model": service.bundle["project_name"],
        "trained_at": service.bundle["trained_at"],
    }


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "message": "CyberTwin Inference API is running.",
        "docs": "/docs",
        "endpoints": {
            "health": "/health",
            "metadata": "/metadata",
            "sample_record": "/sample-record",
            "predict_single": "/predict",
            "predict_batch": "/predict/batch",
            "app_dashboard": "/app/dashboard",
            "app_users": "/app/users",
            "app_nodes": "/app/nodes",
            "app_incidents": "/app/incidents",
            "app_activity": "/app/activity",
            "app_scenarios": "/app/scenarios",
            "app_platform": "/app/platform",
            "app_score_node": "/app/score-node/{node_id}",
            "app_score_batch": "/app/score-batch",
        },
    }


@app.get("/metadata")
def metadata() -> dict[str, Any]:
    return get_service().metadata()


@app.get("/sample-record")
def sample_record() -> dict[str, Any]:
    try:
        return {"record": get_sample_record()}
    except FileNotFoundError as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


@app.post("/predict")
def predict_single(payload: SinglePredictionRequest) -> dict[str, Any]:
    try:
        prediction = get_service().predict([payload.record])[0]
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return {
        "message": "Single record scored successfully.",
        "prediction": prediction,
    }


@app.post("/predict/batch")
def predict_batch(payload: BatchPredictionRequest) -> dict[str, Any]:
    if not payload.records:
        raise HTTPException(status_code=400, detail="At least one record is required.")

    try:
        predictions = get_service().predict(payload.records)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return {
        "message": "Batch scored successfully.",
        "summary": summarize_batch(predictions),
        "predictions": predictions,
    }


@app.get("/app/dashboard")
def app_dashboard() -> dict[str, Any]:
    critical_nodes = sum(1 for node in MOCK_NODES if node["status"] == "critical")
    warning_nodes = sum(1 for node in MOCK_NODES if node["status"] == "warning")
    healthy_nodes = sum(1 for node in MOCK_NODES if node["status"] == "healthy")

    return {
        "project": "CyberTwin",
        "environment": "Hackathon Demo",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_users": len(MOCK_USERS),
            "total_nodes": len(MOCK_NODES),
            "open_incidents": len(MOCK_INCIDENTS),
            "critical_nodes": critical_nodes,
            "warning_nodes": warning_nodes,
            "healthy_nodes": healthy_nodes,
        },
    }


@app.get("/app/users")
def app_users() -> dict[str, Any]:
    return {
        "users": MOCK_USERS,
        "active_user": MOCK_USERS[0],
    }


@app.get("/app/nodes")
def app_nodes() -> dict[str, Any]:
    return {
        "nodes": MOCK_NODES,
    }


@app.get("/app/incidents")
def app_incidents() -> dict[str, Any]:
    return {
        "incidents": MOCK_INCIDENTS,
    }


@app.get("/app/activity")
def app_activity() -> dict[str, Any]:
    return {
        "events": MOCK_ACTIVITY,
    }


@app.get("/app/scenarios")
def app_scenarios() -> dict[str, Any]:
    return {
        "scenarios": MOCK_SCENARIOS,
    }


@app.get("/app/platform")
def app_platform() -> dict[str, Any]:
    return {
        "project": {
            "name": "CyberTwin",
            "tagline": "Digital-twin cyber preparedness for critical infrastructure",
            "about": (
                "CyberTwin is a command platform for simulating cyber incidents across connected city and "
                "critical infrastructure systems before they become real outages."
            ),
            "problem": (
                "Essential infrastructure is highly interconnected, but most cyber tools still react after "
                "damage has already started."
            ),
            "solution": (
                "This app combines a digital twin, fake operational telemetry, and real ML threat scoring so "
                "teams can rehearse attacks, visualize exposure, and prioritize response."
            ),
        },
        "ml_role": {
            "summary": (
                "ML is the intelligence layer. It converts traffic-style telemetry into malicious probability, "
                "attack-family prediction, anomaly probability, and a final risk score."
            ),
            "outputs": [
                "malicious_probability",
                "predicted_attack",
                "attack_confidence",
                "anomaly_probability",
                "risk_score",
                "risk_band",
                "recommended_action",
            ],
            "why_it_matters": [
                "Lets the UI rank nodes by risk instead of just showing static alerts",
                "Turns simulated node activity into a believable threat signal",
                "Gives operators a recommended action, not just a label",
            ],
        },
        "data_boundary": {
            "fake_backend_data": [
                "users",
                "nodes",
                "incidents",
                "activity feed",
                "scenarios",
                "dashboard KPIs",
            ],
            "real_ml_data": [
                "single-node scoring via /app/score-node/{node_id}",
                "estate scoring via /app/score-batch",
                "direct model endpoints /predict and /predict/batch",
            ],
        },
        "frontend_integration": [
            {"method": "GET", "endpoint": "/app/dashboard", "purpose": "Load KPI cards and environment summary"},
            {"method": "GET", "endpoint": "/app/users", "purpose": "Show active operator context"},
            {"method": "GET", "endpoint": "/app/nodes", "purpose": "Render the digital twin inventory"},
            {"method": "GET", "endpoint": "/app/incidents", "purpose": "Render the fake incident command feed"},
            {"method": "GET", "endpoint": "/app/activity", "purpose": "Show timeline and activity updates"},
            {"method": "GET", "endpoint": "/app/scenarios", "purpose": "Populate simulation cards and drills"},
            {"method": "POST", "endpoint": "/app/score-node/{node_id}", "purpose": "Score one node with the real ML model"},
            {"method": "POST", "endpoint": "/app/score-batch", "purpose": "Score many nodes at once for dashboard views"},
        ],
        "backend_integration": {
            "ownership": [
                "Backend owns fake product data and the orchestration layer",
                "Backend should call the trained ML service and return UI-ready payloads",
                "Frontend should prefer /app/* endpoints for product screens",
            ],
            "direct_ml_endpoints": [
                {"method": "GET", "endpoint": "/metadata", "purpose": "Read required fields and model contract"},
                {"method": "POST", "endpoint": "/predict", "purpose": "Score one raw telemetry record"},
                {"method": "POST", "endpoint": "/predict/batch", "purpose": "Score many raw telemetry records"},
            ],
            "recommended_flow": [
                "Frontend calls /app/* for product screens",
                "Backend maps product entities to telemetry records",
                "Backend calls the ML layer",
                "Backend returns prediction plus product context together",
            ],
        },
    }


@app.post("/app/score-node/{node_id}")
def app_score_node(node_id: str) -> dict[str, Any]:
    try:
        node = get_node_by_id(node_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail=f"Unknown node_id: {node_id}") from error

    base_record = get_sample_record()
    record = profile_record(base_record, node["risk_profile"])
    prediction = get_service().predict([record])[0]

    return {
        "message": "Node scored successfully with real ML model.",
        "node": node,
        "prediction": prediction,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/app/score-batch")
def app_score_batch(payload: NodeBatchRequest) -> dict[str, Any]:
    if not payload.node_ids:
        raise HTTPException(status_code=400, detail="At least one node_id is required.")

    sample_record = get_sample_record()
    scored_nodes: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []

    for node_id in payload.node_ids:
        try:
            node = get_node_by_id(node_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=f"Unknown node_id: {node_id}") from error

        record = profile_record(sample_record, node["risk_profile"])
        scored_nodes.append({"node": node, "record": record})
        records.append(record)

    predictions = get_service().predict(records)
    merged = []
    for item, prediction in zip(scored_nodes, predictions):
        merged.append(
            {
                "node": item["node"],
                "prediction": prediction,
            }
        )

    return {
        "message": "Estate scored successfully with the real ML model.",
        "summary": summarize_batch(predictions),
        "scored_nodes": merged,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn

    def pick_available_port(start_port: int, max_tries: int = 20) -> int:
        for port in range(start_port, start_port + max_tries):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if sock.connect_ex(("127.0.0.1", port)) != 0:
                    return port
        raise RuntimeError(f"No available port found in range {start_port}-{start_port + max_tries - 1}")

    start_port = int(os.getenv("API_PORT", "8000"))
    selected_port = pick_available_port(start_port)
    if selected_port != start_port:
        print(f"Port {start_port} is busy, starting API on port {selected_port} instead.")

    uvicorn.run("api:app", host="0.0.0.0", port=selected_port, reload=False)
