from ansible_runner import run
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from json import dumps, loads
from logging import info, warning, error, critical, basicConfig, INFO
from os import getenv, _exit
from pika import BlockingConnection, PlainCredentials, ConnectionParameters
from requests import get
from shutil import rmtree
from sys import exit
from time import sleep
from uuid import uuid4


basicConfig(format=dumps({
    'datetime': '%(asctime)s',
    'loglevel': '[%(levelname)s]',
    'message': '%(message)s'
}), datefmt='%H:%M:%S %d/%m/%Y', level=INFO)

ELASTICSEARCH_HOST         = getenv(key='ELASTICSEARCH_HOST')
ELASTICSEARCH_PORT         = getenv(key='ELASTICSEARCH_PORT')
ELASTICSEARCH_USERNAME     = getenv(key='ELASTICSEARCH_USERNAME')
ELASTICSEARCH_PW           = getenv(key='ELASTICSEARCH_PW')
ELASTICSEARCH_MAX_RESULT   = getenv(key='ELASTICSEARCH_MAX_RESULT')

RABBITMQ_HOST              = getenv(key='RABBITMQ_HOST')
RABBITMQ_MANAGEMENT_PORT   = getenv(key='RABBITMQ_MANAGEMENT_PORT')
RABBITMQ_OPERATION_PORT    = getenv(key='RABBITMQ_OPERATION_PORT')
RABBITMQ_QUEUE_NAME_LISTEN = getenv(key='RABBITMQ_QUEUE_NAME_LISTEN')
RABBITMQ_USERNAME          = getenv(key='RABBITMQ_USERNAME')
RABBITMQ_PASSWORD          = getenv(key='RABBITMQ_PW')

ANSIBLE_FIREWALL_HOST      = getenv(key='ANSIBLE_FIREWALL_HOST')
ANSIBLE_FIREWALL_USERNAME  = getenv(key='ANSIBLE_FIREWALL_USERNAME')
ANSIBLE_FIREWALL_PASSWORD  = getenv(key='ANSIBLE_FIREWALL_PW')
ANSIBLE_CRS_PATH_DIR       = getenv(key='ANSIBLE_CRS_PATH_DIR')
ANSIBLE_MODSEC_CONAME      = getenv(key='ANSIBLE_MODSEC_CONAME')
ANSIBLE_DATA_DIR           = getenv(key='ANSIBLE_DATA_DIR')
ANSIBLE_INVENTORY          = getenv(key='ANSIBLE_INVENTORY')

def main():
    elasticsearch_response = connect_elasticsearch()
    if check_env() is False or elasticsearch_response is False or check_rabbitmq() is False:
        return
    processor(elasticsearch_response=elasticsearch_response)


def check_env():
    info(msg='Checking environment variables...')
    env_vars = {
        'ELASTICSEARCH_HOST': ELASTICSEARCH_HOST,
        'ELASTICSEARCH_PORT': ELASTICSEARCH_PORT,
        'ELASTICSEARCH_USERNAME': ELASTICSEARCH_USERNAME,
        'ELASTICSEARCH_PW': ELASTICSEARCH_PW,
        'ELASTICSEARCH_MAX_RESULT': ELASTICSEARCH_MAX_RESULT,
        'RABBITMQ_HOST': RABBITMQ_HOST,
        'RABBITMQ_MANAGEMENT_PORT': RABBITMQ_MANAGEMENT_PORT,
        'RABBITMQ_OPERATION_PORT': RABBITMQ_OPERATION_PORT,
        'RABBITMQ_QUEUE_NAME_LISTEN': RABBITMQ_QUEUE_NAME_LISTEN,
        'RABBITMQ_USERNAME': RABBITMQ_USERNAME,
        'RABBITMQ_PW': RABBITMQ_PASSWORD,
        'ANSIBLE_FIREWALL_HOST': ANSIBLE_FIREWALL_HOST,
        'ANSIBLE_FIREWALL_USERNAME': ANSIBLE_FIREWALL_USERNAME,
        'ANSIBLE_FIREWALL_PASSWORD': ANSIBLE_FIREWALL_PASSWORD,
        'ANSIBLE_CRS_PATH_DIR': ANSIBLE_CRS_PATH_DIR,
        'ANSIBLE_MODSEC_CONAME': ANSIBLE_MODSEC_CONAME,
        'ANSIBLE_DATA_DIR': ANSIBLE_DATA_DIR,
        'ANSIBLE_INVENTORY': ANSIBLE_INVENTORY
    }
    if not all([value for _, value in env_vars.items()]):
        error(msg=f'Missing required variables: {[key for key, value in env_vars.items() if not value]}')
        return False
    info(msg='Environment variables [OK]')
    return True


def connect_elasticsearch():
    info(msg='Checking Elasticsearch...')
    try:
        elasticsearch_response = Elasticsearch(
            hosts=f'http://{ELASTICSEARCH_HOST}:{ELASTICSEARCH_PORT}', 
            basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PW)
        )
    except ValueError as error_exception:
        error(msg=str(error_exception))
        return False
    while True:
        if elasticsearch_response.ping() is False:
            warning(msg='Ping to Elasticsearch fail, re-ping after 5 seconds')
            sleep(5)
        else:
            break
    info(msg='Elasticsearch [OK]')
    index_settings = {
        "settings": {
            "index": {
                "max_result_window": int(ELASTICSEARCH_MAX_RESULT)
            }
        }
    }
    info(msg='Checking "responser-modsecurity-executions" index...')
    if not elasticsearch_response.indices.exists(index='responser-modsecurity-executions'):
        info(msg='Creating "responser-modsecurity-executions"')
        elasticsearch_response.indices.create(index="responser-modsecurity-executions", body=index_settings)
        info(msg='Created "responser-modsecurity-executions"')
    info(msg='"responser-modsecurity-executions" [OK]')
    return elasticsearch_response


def check_rabbitmq():
    info(msg='Checking RabbitMQ...')
    try:
        rabbitmq_response = get(
            url=f'http://{RABBITMQ_HOST}:{RABBITMQ_MANAGEMENT_PORT}/api/healthchecks/node', 
            auth=(RABBITMQ_USERNAME, RABBITMQ_PASSWORD)
        )
        if rabbitmq_response.status_code != 200:
            error(msg=f'RabbitMQ connection testing fail, status code {rabbitmq_response.status_code}')
            return False
    except:
        error(msg='Can\'t perform GET request to RabbitMQ, fail for connection testing')
        return False
    info(msg='RabbitMQ [OK]')
    return True


def processor(elasticsearch_response: Elasticsearch):
    connection = BlockingConnection(
        ConnectionParameters(
            host=RABBITMQ_HOST,
            port=RABBITMQ_OPERATION_PORT,
            credentials=PlainCredentials(
                username=RABBITMQ_USERNAME,
                password=RABBITMQ_PASSWORD
            )
        )
    )
    channel = connection.channel()
    channel.queue_declare(queue=RABBITMQ_QUEUE_NAME_LISTEN, durable=True)
    def callback(ch, method, properties, body: bytes):
        extra_vars = {
            'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
            'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
            'modsec_container_name': ANSIBLE_MODSEC_CONAME
        }
        request_body: dict = loads(body.decode())
        responser_name = request_body.get('responser_name')
        modsec_type = request_body.get('type')
        secrule_id = request_body.get('id')
        secrule_id_ip = None; secrule_id_chain = None
        ip = request_body.get('ip')
        ip_source = None; anomaly_score = None; paranoia_level = None
        rule = request_body.get('rule')
        payload = request_body.get('payload')
        hashed_rule = request_body.get('hashed_rule')
        hashed_payload = request_body.get('hashed_payload')
        executions_id = request_body.get('executions_id')
        modsec_execution_for_ip = None; modsec_execution_for_chain = None
        playbook = None
        print(request_body)
        unique_id_first = uuid4()
        unique_id_second = uuid4()
        is_duplicated = False
        modsec_execution_all = elasticsearch_response.search(index='responser-modsecurity-executions', query={'match_all': {}}, size=ELASTICSEARCH_MAX_RESULT).raw['hits']['hits']
        if modsec_type == 'full':
            secrule_id_ip = secrule_id.get('secrule_id_for_ip')
            secrule_id_chain = secrule_id.get('secrule_id_for_chain')
            ip_source = ip.get('ip_source')
            modsec_execution_for_ip = executions_id.get('for_ip')
            modsec_execution_for_chain = executions_id.get('for_chain')
            if [
                entity for entity in modsec_execution_all
                if entity['_source']['detail_ip'] == ip_source
                and entity['_source']['detail_hashed_rule'] == hashed_rule
                and entity['_source']['detail_hashed_payload'] == hashed_payload
            ].__len__() > 1:
                is_duplicated = True
            else:
                anomaly_score = ip.get('anomaly_score')
                paranoia_level = ip.get('paranoia_level')
                playbook = f'{ANSIBLE_DATA_DIR}/playbooks/ansible_apply_full_modsecurity.yaml'
                extra_vars['secrule_anomaly_score'] = anomaly_score
                extra_vars['secrule_paranoia_level'] = paranoia_level
                extra_vars['secrule_regex'] = rule
                extra_vars['secrule_id_ip'] = secrule_id_ip
                extra_vars['secrule_id_chain'] = secrule_id_chain
                extra_vars['secrule_ip'] = ip_source
                extra_vars['secrule_file'] = f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{secrule_id_ip}-{secrule_id_chain}-{unique_id_first}'
        elif modsec_type == 'onlyRegexAndPayload':
            modsec_execution = executions_id.get('single')
            if [
                entity for entity in modsec_execution_all
                if entity['_source']['detail_ip'] is None
                and entity['_source']['detail_hashed_rule'] == hashed_rule
                and entity['_source']['detail_hashed_payload'] == hashed_payload
            ].__len__() > 1:
                is_duplicated = True
            else:
                secrule_id = secrule_id.get('secrule_id')
                playbook = f'{ANSIBLE_DATA_DIR}/playbooks/ansible_apply_only_regex_payload_modsecurity.yaml'
                extra_vars['secrule_regex'] = rule
                extra_vars['secrule_id'] = secrule_id
                extra_vars['secrule_file'] = f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{secrule_id}-{unique_id_first}'
        elif modsec_type == 'onlyPayload':
            modsec_execution = executions_id.get('single')
            if [
                entity for entity in modsec_execution_all
                if entity['_source']['detail_ip'] is None
                and entity['_source']['detail_hashed_rule'] is None
                and entity['_source']['detail_hashed_payload'] == hashed_payload
            ].__len__() > 1:
                is_duplicated = True
            else:
                secrule_id = secrule_id.get('secrule_id')
                playbook = f'{ANSIBLE_DATA_DIR}/playbooks/ansible_apply_only_payload_modsecurity.yaml'
                extra_vars['secrule_payload'] = payload
                extra_vars['secrule_id'] = secrule_id
                extra_vars['secrule_file'] = f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{secrule_id}-{unique_id_first}'
        elif modsec_type == 'onlyIP':
            secrule_id = secrule_id.get('secrule_id')
            ip_source = ip.get('ip_source')
            modsec_execution = executions_id.get('single')
            if [
                entity for entity in modsec_execution_all
                if entity['_source']['detail_ip'] == ip_source
                and entity['_source']['detail_hashed_rule'] is None
                and entity['_source']['detail_hashed_payload'] is None
            ].__len__() > 1:
                is_duplicated = True
            else:
                anomaly_score = ip.get('anomaly_score')
                paranoia_level = ip.get('paranoia_level')
                playbook = f'{ANSIBLE_DATA_DIR}/playbooks/ansible_apply_only_ip_modsecurity.yaml'
                extra_vars['secrule_ip'] = ip_source
                extra_vars['secrule_id'] = secrule_id
                extra_vars['secrule_anomaly_score'] = anomaly_score
                extra_vars['secrule_paranoia_level'] = paranoia_level
                extra_vars['secrule_file'] = f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{secrule_id}-{unique_id_first}'
        elif modsec_type == 'onlyIPAndRegex':
            secrule_id_ip = secrule_id.get('secrule_id_for_ip')
            secrule_id_chain = secrule_id.get('secrule_id_for_chain')
            ip_source = ip.get('ip_source')
            modsec_execution_for_ip = executions_id.get('for_ip')
            modsec_execution_for_chain = executions_id.get('for_chain')
            if [
                entity for entity in modsec_execution_all
                if entity['_source']['detail_ip'] == ip_source
                and entity['_source']['detail_hashed_rule'] == hashed_rule
                and entity['_source']['detail_hashed_payload'] is None
            ].__len__() > 1:
                is_duplicated = True
            else:
                anomaly_score = ip.get('anomaly_score')
                paranoia_level = ip.get('paranoia_level')
                playbook = f'{ANSIBLE_DATA_DIR}/playbooks/ansible_apply_only_ip_regex_modsecurity.yaml'
                extra_vars['secrule_anomaly_score'] = anomaly_score
                extra_vars['secrule_paranoia_level'] = paranoia_level
                extra_vars['secrule_regex'] = rule
                extra_vars['secrule_id_ip'] = secrule_id_ip
                extra_vars['secrule_id_chain'] = secrule_id_chain
                extra_vars['secrule_ip'] = ip_source
                extra_vars['secrule_file'] = f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{secrule_id_ip}-{secrule_id_chain}-{unique_id_first}'
        elif modsec_type == 'onlyRegex':
            modsec_execution = executions_id.get('single')
            if [
                entity for entity in modsec_execution_all
                if entity['_source']['detail_ip'] is None
                and entity['_source']['detail_hashed_rule'] == hashed_rule
                and entity['_source']['detail_hashed_payload'] is None
            ].__len__() > 1:
                is_duplicated = True
            else:
                secrule_id = secrule_id.get('secrule_id')
                playbook = f'{ANSIBLE_DATA_DIR}/playbooks/ansible_apply_only_regex_modsecurity.yaml'
                extra_vars['secrule_regex'] = rule
                extra_vars['secrule_id'] = secrule_id
                extra_vars['secrule_file'] = f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{secrule_id}-{unique_id_first}'
        elif modsec_type == 'onlyIPAndPayload':
            secrule_id_ip = secrule_id.get('secrule_id_for_ip')
            secrule_id_chain = secrule_id.get('secrule_id_for_chain')
            ip_source = ip.get('ip_source')
            modsec_execution_for_ip = executions_id.get('for_ip')
            modsec_execution_for_chain = executions_id.get('for_chain')
            if [
                entity for entity in modsec_execution_all
                if entity['_source']['detail_ip'] == ip_source
                and entity['_source']['detail_hashed_rule'] is None
                and entity['_source']['detail_hashed_payload'] == hashed_payload
            ].__len__() > 1:
                is_duplicated = True
            else:
                anomaly_score = ip.get('anomaly_score')
                paranoia_level = ip.get('paranoia_level')
                playbook = f'{ANSIBLE_DATA_DIR}/playbooks/ansible_apply_only_ip_payload_modsecurity.yaml'
                extra_vars['secrule_anomaly_score'] = anomaly_score
                extra_vars['secrule_paranoia_level'] = paranoia_level
                extra_vars['secrule_payload'] = payload
                extra_vars['secrule_id_ip'] = secrule_id_ip
                extra_vars['secrule_id_chain'] = secrule_id_chain
                extra_vars['secrule_ip'] = ip_source
                extra_vars['secrule_file'] = f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{secrule_id_ip}-{secrule_id_chain}-{unique_id_first}'
        is_error = False
        if is_duplicated == False:
            runner = run(
                private_data_dir=ANSIBLE_DATA_DIR,
                playbook=playbook,
                inventory=ANSIBLE_INVENTORY,
                host_pattern='firewall',
                json_mode=True,
                quiet=True,
                ident=f'{unique_id_first}-{unique_id_second}',
                extravars=extra_vars
            )
            for event in runner.events:
                if event.get('event') == 'runner_on_unreachable':
                    is_error = event['stdout']
                    break
                if event.get('event') == 'runner_on_failed':
                    is_error = event['stdout']
                    break
            if runner.status == 'failed':
                elasticsearch_response.index(index='responser-modsecurity-errorlogs', document={
                    'responser_name': responser_name,
                    'message': event['stdout'],
                    'pattern': 'ansible_playbook'
                })
                critical(msg=dumps(event['stdout']))
                is_error = True
        time_now = datetime.now() + timedelta(hours=7)
        format_time_now = f'{time_now.hour}:{time_now.minute}:{time_now.second} {time_now.day}/{time_now.month}/{time_now.year}'
        if modsec_type in ['full', 'onlyIPAndRegex', 'onlyIPAndPayload']:
            if is_duplicated is True:
                modify_double_secrule(
                    elasticsearch_response=elasticsearch_response,
                    modsec_execution_for_ip=modsec_execution_for_ip,
                    modsec_execution_for_chain=modsec_execution_for_chain,
                    start=None,
                    status='duplicated'
                )
            else:
                if is_error is True:
                    modify_double_secrule(
                        elasticsearch_response=elasticsearch_response,
                        modsec_execution_for_ip=modsec_execution_for_ip,
                        modsec_execution_for_chain=modsec_execution_for_chain,
                        start=None,
                        status='error'
                    )
                else:
                    modify_double_secrule(
                        elasticsearch_response=elasticsearch_response,
                        modsec_execution_for_ip=modsec_execution_for_ip,
                        modsec_execution_for_chain=modsec_execution_for_chain,
                        start=format_time_now,
                        status='running'
                    )
        elif modsec_type in ['onlyRegexAndPayload', 'onlyPayload', 'onlyIP', 'onlyRegex']:
            if is_duplicated is True:
                modify_single_secrule(
                    elasticsearch_response=elasticsearch_response,
                    modsec_execution=modsec_execution,
                    start=None,
                    status='duplicated'
                )
            else:
                if is_error is True:
                    modify_single_secrule(
                        elasticsearch_response=elasticsearch_response,
                        modsec_execution=modsec_execution,
                        start=None,
                        status='error'
                    )
                else:
                    modify_single_secrule(
                        elasticsearch_response=elasticsearch_response,
                        modsec_execution=modsec_execution,
                        start=format_time_now,
                        status='running'
                    )
        rmtree(path=f'{ANSIBLE_DATA_DIR}/artifacts/{unique_id_first}-{unique_id_second}', ignore_errors=True)
        ch.basic_ack(delivery_tag=method.delivery_tag)
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue=RABBITMQ_QUEUE_NAME_LISTEN, on_message_callback=callback)
    channel.start_consuming()


def modify_double_secrule(
    elasticsearch_response: Elasticsearch,
    modsec_execution_for_ip: str,
    modsec_execution_for_chain: str,
    start: str,
    status: str
):
    elasticsearch_response.update(
        index='responser-modsecurity-executions', 
        id=modsec_execution_for_ip,
        doc={
            'start': start,
            'status': status
        }
    )
    elasticsearch_response.update(
        index='responser-modsecurity-executions', 
        id=modsec_execution_for_chain,
        doc={
            'start': start,
            'status': status
        }
    )


def modify_single_secrule(
    elasticsearch_response: Elasticsearch,
    modsec_execution: str,
    start: str,
    status: str
):
    elasticsearch_response.update(
        index='responser-modsecurity-executions', 
        id=modsec_execution,
        doc={
            'start': start,
            'status': status
        }
    )


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        try:
            exit(0)
        except SystemExit:
            _exit(0)
