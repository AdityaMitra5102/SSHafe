import glob
from pathlib import Path
from collections import deque
import numpy as np
import pandas as pd
import joblib
import os

secrets='/etc/secrets'
MODELS_DIR=os.path.join(secrets, 'models')


class SSHBruteForceDetector:
    """
    Online SSH brute-force detector.
    Feed raw log lines one at a time via .ingest().
    Returns a score (0-1) and alert flag per line.
    """

    def __init__(self, model, scaler, threshold, feat_cols, window_sizes=[30, 60, 300]):
        self.model = model
        self.scaler = scaler
        self.threshold = threshold
        self.feat_cols = feat_cols
        self.window_sizes = window_sizes
        self.ip_buffers = {}
        self.max_window = max(window_sizes)

    def _get_buffer(self, ip):
        if ip not in self.ip_buffers:
            self.ip_buffers[ip] = deque()
        return self.ip_buffers[ip]

    def _prune(self, buf, now):
        while buf and (now - buf[0][0]) > self.max_window:
            buf.popleft()

    def _extract_features(self, buf, now):
        feats = {}
        for w in self.window_sizes:
            window = [e for e in buf if (now - e[0]) <= w]
            n = len(window)
            if n == 0:
                feats.update({f'w{w}_{k}': 0 for k in [
                    'n_attempts','attempt_rate','fail_ratio','unique_users',
                    'iat_mean','iat_std','iat_min','iat_cv',
                    'n_accepted','n_failed_pw','n_invalid'
                ]})
                continue

            statuses   = [e[1] for e in window]
            usernames  = [e[2] for e in window]
            events     = [e[3].lower() for e in window]
            timestamps = sorted([e[0] for e in window])

            n_failed  = sum(1 for s in statuses if s.lower() != 'success')
            fail_ratio = n_failed / n
            unique_users = len(set(usernames))
            attempt_rate = n / w

            iats = np.diff(timestamps) if len(timestamps) > 1 else np.array([0])
            iat_mean = iats.mean()
            iat_std  = iats.std()
            iat_min  = iats.min()
            iat_cv   = iat_std / iat_mean if iat_mean > 0 else 0

            n_accepted  = sum(1 for e in events if 'accept' in e)
            n_failed_pw = sum(1 for e in events if 'fail' in e)
            n_invalid   = sum(1 for e in events if 'invalid' in e)

            feats.update({
                f'w{w}_n_attempts':   n,
                f'w{w}_attempt_rate': attempt_rate,
                f'w{w}_fail_ratio':   fail_ratio,
                f'w{w}_unique_users': unique_users,
                f'w{w}_iat_mean':     iat_mean,
                f'w{w}_iat_std':      iat_std,
                f'w{w}_iat_min':      iat_min,
                f'w{w}_iat_cv':       iat_cv,
                f'w{w}_n_accepted':   n_accepted,
                f'w{w}_n_failed_pw':  n_failed_pw,
                f'w{w}_n_invalid':    n_invalid,
            })
        return feats

    def ingest(self, timestamp, source_ip, username, event_type, status):
        if isinstance(timestamp, str):
            ts = pd.Timestamp(timestamp).timestamp()
        elif isinstance(timestamp, pd.Timestamp):
            ts = timestamp.timestamp()
        else:
            ts = float(timestamp)

        buf = self._get_buffer(source_ip)
        self._prune(buf, ts)
        buf.append((ts, status, username, event_type))

        feats = self._extract_features(buf, ts)
        feat_vec_ordered = np.array([feats.get(col, 0) for col in self.feat_cols]).reshape(1, -1)

        if self.scaler is not None:
            model_input = feat_vec_ordered
        else:
            model_input = feat_vec_ordered

        score = float(self.model.predict_proba(model_input)[0, 1])
        alert = score >= self.threshold

        return {
            'source_ip': source_ip,
            'timestamp': timestamp,
            'score': round(score, 4),
            'alert': bool(alert),
            'features': feats
        }

    def ingest_log(self, log):
        out=self.ingest(log['timestamp'], log['source_ip'], log['username'], log['event_type'], log['status'])
        log['prediction']=out
        return log

    def process_csv(self, df_raw):
        required_cols = ['timestamp', 'source_ip', 'username', 'event_type', 'status']
        missing = [c for c in required_cols if c not in df_raw.columns]
        if missing:
            raise ValueError(f'Missing required columns: {missing}')

        results = []
        for idx, row in df_raw.iterrows():
            result = self.ingest(
                timestamp=row['timestamp'],
                source_ip=row['source_ip'],
                username=row['username'],
                event_type=row['event_type'],
                status=row['status']
            )
            results.append({
                'timestamp': result['timestamp'],
                'source_ip': result['source_ip'],
                'score': result['score'],
                'alert': result['alert'],
                'original_index': idx
            })
        return pd.DataFrame(results)
        

model_path = os.path.join(MODELS_DIR, 'lgb_ssh_detector.pkl')
scaler_path = os.path.join(MODELS_DIR, 'scaler.pkl')
config_path = os.path.join(MODELS_DIR, 'detector_config.pkl')
#assert model_path.exists(), f'Missing model file: {model_path}'
#assert config_path.exists(), f'Missing config file: {config_path}'

saved_model = joblib.load(model_path)
saved_scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None
saved_config = joblib.load(config_path)

print(saved_config)


best_thresh = float(saved_config['threshold'])
feat_cols = list(saved_config['feat_cols'])
WINDOW_SIZES = list(saved_config['window_sizes'])

print('Loaded artifacts from models/:')
print(f'  threshold: {best_thresh:.4f}')
print(f'  feature count: {len(feat_cols)}')
print(f'  windows: {WINDOW_SIZES}')
detector = SSHBruteForceDetector(
    model=saved_model,
    scaler=saved_scaler,
    threshold=best_thresh,
    feat_cols=feat_cols,
    window_sizes=WINDOW_SIZES
)
