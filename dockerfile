FROM python:3

WORKDIR /receivers

COPY requirements.txt ./
RUN apt update -y && apt install -y ansible sshpass && pip install --no-cache-dir -r requirements.txt

COPY . .

ENV ELASTICSEARCH_HOST="elasticsearch" \
    ELASTICSEARCH_PORT=9200 \
    ELASTICSEARCH_USERNAME="elastic" \
    ELASTICSEARCH_PW="elastic" \
    ELASTICSEARCH_MAX_RESULT=1000000000 \
    RABBITMQ_HOST="rabbitmq" \
    RABBITMQ_MANAGEMENT_PORT=15672 \
    RABBITMQ_OPERATION_PORT=5672 \
    RABBITMQ_QUEUE_NAME_LISTEN="modsecurity-apply" \
    RABBITMQ_USERNAME="guest" \
    RABBITMQ_PW="guest" \
    ANSIBLE_FIREWALL_HOST="192.168.1.9" \
    ANSIBLE_FIREWALL_USERNAME="root" \
    ANSIBLE_FIREWALL_PW="cxt" \
    ANSIBLE_CRS_PATH_DIR="/crs" \
    ANSIBLE_MODSEC_CONAME="modsecurity" \
    ANSIBLE_DATA_DIR="/receivers/config/." \
    ANSIBLE_INVENTORY="/receivers/config/hosts"

CMD [ "python", "./run.py" ]
