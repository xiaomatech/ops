#!/usr/bin/env bash
cpu_count=`python -c "import multiprocessing;print multiprocessing.cpu_count()-1"`
gunicorn  -w $cpu_count server:app  --daemon  -b '0.0.0.0:8000' -k gevent_pywsgi \
    --access-logfile=./logs/access.log --error-logfile=./logs/gunicorn_error.log \
    --pid=/var/run/gunicorn.pid --keep-alive=1 --backlog=4096
