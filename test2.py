with open(file='payload.txt', mode='r') as payload:
    payload = payload.readlines()

import requests

url = "http://192.168.1.9:9947/xsss/default-xss-analyzer"

data = {
    "@timestamp": "2024-11-28T22:30:28.000Z",
    "response_time": 0.292,
    "status_code": 200,
    "timestamp": "28/Nov/2024:22:30:28 +0000",
    "event": {},
    "ip_address": "192.168.1.2",
    "agent": {
        "name": "6c64ea918f16",
        "type": "filebeat",
        "version": "8.15.1",
        "ephemeral_id": "2639342f-280e-48ad-b3ae-75b7bd2ab529",
        "id": "7ba1f7df-008e-45f8-99b4-2b6c1e20be9a"
    },
    "request_body": "search=%253Cscript%253Ealert('XSS')%253C%252Fscript%253E",
    "response_size": 5047,
    "input": {
        "type": "log"
    },
    "log": {
        "offset": 12446,
        "file": {
            "path": "/nginx-logs/access.log"
        }
    },
    "request_header": "POST /api/rooms/index.php HTTP/1.1",
    "referer": "http://192.168.1.11/welcome.php",
    "user_identifier": "-",
    "ecs": {
        "version": "8.0.0"
    },
    "tags": [
        "beats_input_codec_plain_applied"
    ],
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "host": {
        "name": "6c64ea918f16"
    },
    "@version": "1"
}

headers = {
    "Content-Type": "application/json",
}

for pl in payload:
    data["request_body"] = f'search={pl.replace('\\n', '')}'
    response = requests.post(url, json=data, headers=headers)
    print(f"Status code: {response.status_code}")
    print(f"Response body: {response.text}")
