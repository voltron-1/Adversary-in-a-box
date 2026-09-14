FROM python:3.14-slim

LABEL maintainer="Adversary-in-a-Box Lab"
LABEL description="Forensic scoreboard — MTTD/MTTA tiered scoring dashboard (OQ-5)"

RUN set -e && \
    echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries && \
    rc=1 ; \
    for attempt in 1 2 3 ; do \
        apt-get update -qq && \
        apt-get install -y --no-install-recommends curl && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists/* && \
        { rc=0 ; break ; } ; \
        echo "[apt] attempt ${attempt} failed, refreshing index and retrying in 30s..." >&2 ; \
        rm -rf /var/lib/apt/lists/* ; \
        sleep 30 ; \
    done ; \
    if [ "${rc}" -ne 0 ]; then \
        echo "[apt] all 3 install attempts failed -- aborting build" >&2 ; \
        exit 1 ; \
    fi

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py scorer.py sigma_eval.py ./
COPY templates ./templates

RUN mkdir -p /evidence

EXPOSE 5002

CMD ["python", "app.py"]
