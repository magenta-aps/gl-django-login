FROM python:3.8
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update && apt-get install -y --no-install-recommends \
 libxmlsec1-dev\
 && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY ./src /app
WORKDIR /app
CMD ["python", "-m", "unittest"]
