"""One TensorFlow worker and one persistent SQLite database for the demo."""
import os

bind = '0.0.0.0:' + os.environ.get('PORT', '10000')
workers = 1
worker_class = 'gthread'
threads = 2
timeout = 120
graceful_timeout = 30
preload_app = False
accesslog = None
errorlog = '-'
capture_output = True
