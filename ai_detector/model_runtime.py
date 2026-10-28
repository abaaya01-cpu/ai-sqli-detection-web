"""Explicit, validated artifact contract. No pickle is loaded by the website."""
import hashlib
import json
import math
from pathlib import Path
from .preprocessing import normalize


class ModelRuntime:
    def __init__(self, directory):
        import tensorflow as tf
        from tensorflow.keras.models import load_model
        from tensorflow.keras.preprocessing.text import tokenizer_from_json
        root = Path(directory)
        self.config = json.loads((root / 'config.json').read_text(encoding='utf-8'))
        c = self.config
        if c.get('schema_version') != 1 or c.get('preprocessing') not in ('raw', 'normalize_v1'):
            raise ValueError('Unsupported artifact preprocessing contract')
        if c.get('padding') not in ('pre', 'post') or c.get('truncating') not in ('pre', 'post'):
            raise ValueError('Explicit padding and truncation required')
        if not isinstance(c.get('maxlen'), int) or not 1 <= c['maxlen'] <= 8192:
            raise ValueError('Invalid sequence length')
        filename = c.get('model_file')
        if filename not in ('model.h5', 'model.keras'):
            raise ValueError('Unsupported model filename')
        for name in (filename, 'tokenizer.json'):
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != c.get('sha256', {}).get(name):
                raise ValueError('Artifact checksum mismatch')
        self.tokenizer = tokenizer_from_json((root / 'tokenizer.json').read_text(encoding='utf-8'))
        self.model = load_model(root / filename, compile=False)
        shape = self.model.input_shape
        if len(shape) != 2 or shape[1] not in (None, c['maxlen']) or self.model.output_shape[-1] != 1:
            raise ValueError('Unexpected model input/output shape')
        embedding = next(layer for layer in self.model.layers if hasattr(layer, 'input_dim'))
        usable_ids = [i for i in self.tokenizer.word_index.values()
                      if self.tokenizer.num_words is None or i < self.tokenizer.num_words]
        if usable_ids and max(usable_ids) >= embedding.input_dim:
            raise ValueError('Tokenizer vocabulary exceeds embedding capacity')
        if any(not math.isfinite(float(w.min())) or not math.isfinite(float(w.max())) for w in self.model.get_weights()):
            raise ValueError('Model has non-finite weights')
        # Trace once per fixed artifact length. A dynamic batch dimension allows
        # both request-time single inputs and offline batches without retracing.
        self._infer = tf.function(lambda x:self.model(x, training=False),
            input_signature=[tf.TensorSpec(shape=(None,c['maxlen']),dtype=tf.int32)])
        self.predict_many(['startup compatibility probe'])

    def predict_many(self, texts):
        import numpy as np
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        c = self.config
        prepared = [normalize(t) if c['preprocessing'] == 'normalize_v1' else str(t) for t in texts]
        x = pad_sequences(self.tokenizer.texts_to_sequences(prepared), maxlen=c['maxlen'],
                          padding=c['padding'], truncating=c['truncating'])
        y = np.asarray(self._infer(x).numpy())
        if y.shape != (len(texts), 1):
            raise ValueError('Unexpected prediction shape')
        values = [float(p) for p in y[:, 0]]
        if any(not math.isfinite(p) or not 0 <= p <= 1 for p in values):
            raise ValueError('Model returned an invalid probability')
        return values

    def predict(self, text):
        return self.predict_many([text])[0]
