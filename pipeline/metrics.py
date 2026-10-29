"""Evaluation metrics for the trained autoencoder against LID-DS ground
truth. Per IMPLEMENTATION_PLAN.md's evaluation-granularity decision:
per-window is primary (matches what the model actually scores),
per-attack-instance recall/latency is secondary (more narratively useful for
the demo -- "did we catch the attack at all, how fast").
"""

from typing import List, Dict

from sklearn.metrics import precision_recall_fscore_support, roc_auc_score


def per_window_metrics(y_true: List[bool], y_pred: List[bool], scores: List[float]) -> Dict:
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    result = {"precision": precision, "recall": recall, "f1": f1}
    if len(set(y_true)) > 1:
        result["roc_auc"] = roc_auc_score(y_true, scores)
    return result


def per_attack_instance_recall(recordings: List[Dict]) -> Dict:
    """recordings: list of {"is_attack_recording": bool, "any_attack_window_flagged": bool}.
    Returns the fraction of actual attack recordings where at least one
    attack-phase window was flagged anomalous."""
    attack_recordings = [r for r in recordings if r["is_attack_recording"]]
    if not attack_recordings:
        return {"n_attack_recordings": 0, "recall": None}
    detected = sum(1 for r in attack_recordings if r["any_attack_window_flagged"])
    return {
        "n_attack_recordings": len(attack_recordings),
        "detected": detected,
        "recall": detected / len(attack_recordings),
    }
