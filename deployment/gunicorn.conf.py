"""One synchronous TensorFlow worker for the free SQLite demonstration."""
import os

bind = '0.0.0.0:' + os.environ.get('PORT', '10000')
workers = 1
worker_class = 'sync'
threads = 1
timeout = 120
graceful_timeout = 30
preload_app = False
accesslog = None
errorlog = '-'
capture_output = True
