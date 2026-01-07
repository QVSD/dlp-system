from collections import defaultdict
import time

# counters simple (in-memory)
_counters = defaultdict(int)
_start_time = time.time()


def inc(metric_name: str, labels: dict = None):
    key = _build_key(metric_name, labels)
    _counters[key] += 1


def get_metrics():
    return {
        "uptime_seconds": int(time.time() - _start_time),
        "metrics": dict(_counters)
    }


def _build_key(name, labels):
    if not labels:
        return name

    label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
    return f"{name}{{{label_str}}}"
