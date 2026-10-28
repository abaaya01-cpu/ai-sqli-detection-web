"""Separate rule evidence, neural probabilities and request decision policy."""
import math
import os
import re
from threading import Lock
from .preprocessing import normalize, MAX_INPUT

RULES = [
    ('boolean', r"(?:\bor\b|\band\b)\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*')", .85),
    ('union', r'\bunion\s+(?:all\s+)?select\b', .95),
    ('time', r'\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b', .95),
    ('error', r'\b(?:extractvalue|updatexml)\s*\(', .9),
    ('stacked', r'\b(?:drop|truncate)\s+table\b', .95),
    ('comment', r"['\"]\s*(?:--|#|/\*)", .65),
]
RULES = [(name, re.compile(pattern, re.I), weight) for name, pattern, weight in RULES]

def match_rules(value):
    text = normalize(value)
    variants = [text, re.sub(r'/\*.*?\*/', '', text), re.sub(r'/\*.*?\*/', ' ', text)]
    hits = [(n, w) for n, pattern, w in RULES if any(pattern.search(v) for v in variants)]
    return {'rule_score': max([w for _, w in hits], default=0.),
            'indicators': [n for n, _ in hits], 'category': hits[0][0] if hits else 'unknown'}

def effective_rule_score(value, context, raw_score):
    """SQL discussion is reviewable; terms alone cannot block prose.

    This is a lexical heuristic, not proof of benign intent. Parameterized SQL
    remains the independent protection against injection.
    """
    if context not in ('message', 'name', 'full_name') or not raw_score:
        return raw_score
    text = re.sub(r'/\*.*?\*/', '', normalize(value))
    direct = re.match(r"^(?:['\"`]|\d+\s*(?:['\"]|\b(?:or|and)\b)|union\b|(?:drop|truncate)\s+table\b|(?:sleep|benchmark|pg_sleep|extractvalue|updatexml)\s*\()", text)
    boundary = re.search(r"['\"]\s*(?:or|and)\b|;\s*(?:select|drop|truncate|delete|update|waitfor)\b", text)
    prose = re.match(r'^(?:please|can you|how|what|why|i|we|the|this|our|a|an|in|for|explain|example|warning|tutorial|note|do not|never)\b', text)
    return min(raw_score, .6) if prose or not (direct or boundary) else raw_score

def decide(rule_score, probability, context, policy, mode):
    score = rule_score if mode == 'rules-only' else (probability if mode == 'lstm' else max(rule_score, probability))
    source = 'rules' if mode == 'rules-only' else ('lstm' if mode == 'lstm' or probability > rule_score else 'rules')
    threshold = policy[{'rules-only':'rules_block', 'lstm':'lstm_block', 'hybrid':'hybrid_block'}[mode]]
    # The experimental model was trained on messages/fragments, not names,
    # emails or secrets. Preserve its numerical output for observability, but
    # exclude it from decisions outside that domain (including review flags).
    if context in ('password', 'confirm_password', 'email', 'full_name', 'name'):
        score, source, threshold = rule_score, 'rules', policy['rules_block']
    block = score >= threshold
    review = score >= policy['review']
    # Bound credential lookups give passwords no executable SQL semantics.
    if context in ('password', 'confirm_password'):
        block = False
    decision = 'BLOCK' if block else 'REVIEW' if review else 'ALLOW'
    return score, decision, source

class Detector:
    def __init__(self, model_dir=None, mode=None):
        self.model_dir, self.requested_mode = model_dir, mode
        self.model = self.tokenizer = self.runtime = None
        self.error = None
        self.last_inference_error = None
        self.loaded = False
        self.lock = Lock()
        self.config = {'maxlen': 256, 'block': .8, 'review': .45}
        self.policy = {'rules_block': .8, 'lstm_block': .8, 'hybrid_block': .8, 'review': .45,
                       'selection': 'provisional; no validation-selected policy configured'}
        self.mode = 'rules-only'

    def load(self):
        with self.lock:
            if self.loaded:
                return
            directory = self.model_dir or os.getenv('SQLI_MODEL_DIR')
            requested = self.requested_mode or os.getenv('SQLI_MODE', 'hybrid' if directory else 'rules-only')
            if requested not in ('rules-only', 'lstm', 'hybrid'):
                self.error = 'Invalid requested mode; rules-only fallback'
            elif requested == 'rules-only':
                self.error = 'Rules-only mode explicitly selected'
            elif not directory:
                self.error = 'No model artifact configured; rules-only fallback'
            else:
                original_policy = dict(self.policy)
                try:
                    from .model_runtime import ModelRuntime
                    self.runtime = ModelRuntime(directory)
                    self.config.update(self.runtime.config)
                    self.policy.update(self.runtime.config.get('policy', {}))
                    for name in ('rules_block', 'lstm_block', 'hybrid_block', 'review'):
                        v = self.policy[name]
                        if not isinstance(v, (float, int)) or not math.isfinite(v) or not 0 <= v <= 1:
                            raise ValueError('Invalid decision threshold')
                    if self.policy['review'] >= min(self.policy[k] for k in ('rules_block','lstm_block','hybrid_block')):
                        raise ValueError('Review threshold must be below all block thresholds')
                    self.model, self.tokenizer = self.runtime.model, self.runtime.tokenizer
                    self.mode = requested
                except Exception as exc:
                    self.runtime = self.model = self.tokenizer = None
                    self.policy = original_policy
                    self.config = {'maxlen':256, 'block':.8, 'review':.45}
                    self.error = f'Model load failed ({type(exc).__name__}); rules-only fallback'
            self.loaded = True

    def status(self):
        self.load()
        return {'mode': self.mode, 'error': self.error, 'artifact': self.config.get('artifact_id', 'none'),
                'last_inference_error':self.last_inference_error,
                'policy_selection': self.policy['selection']}

    def analyze(self, value, context='text'):
        self.load()
        result = match_rules(value)
        rule_score = effective_rule_score(value, context, result['rule_score'])
        probability = None
        mode, error = self.mode, self.error
        if self.runtime is not None:
            try:
                with self.lock:
                    probability = float(self.runtime.predict(value))
                if not math.isfinite(probability) or not 0 <= probability <= 1:
                    raise ValueError('Invalid model probability')
                self.last_inference_error = None
            except Exception as exc:
                mode = 'rules-only'
                error = f'Model inference failed ({type(exc).__name__}); rules-only fallback for this event'
                self.last_inference_error = error
                probability = None
        score, decision, source = decide(rule_score, probability, context, self.policy, mode)
        if len(str(value)) > MAX_INPUT:
            result['indicators'].append('oversize_input')
            score, decision, source = 1., 'BLOCK', 'input-limit'
        return dict(result, score=score, effective_rule_score=rule_score, model_probability=probability, decision=decision,
                    risk='high' if decision == 'BLOCK' else 'medium' if decision == 'REVIEW' else 'low',
                    model_status=error or 'available', model_error=error, mode=mode,
                    decision_source=source, context=context)

detector = Detector()

def detect_sqli(payload):
    return detector.analyze(payload)['score']
