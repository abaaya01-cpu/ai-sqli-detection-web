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


def post_worker_init(worker):
    # Gunicorn can import the WSGI module for validation in its parent process.
    # Initialize TensorFlow only after the serving worker has been forked.
    from deployment.wsgi import initialize_worker
    initialize_worker()
