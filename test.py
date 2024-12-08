import asyncio
import aiohttp

async def send_request(url, session, method="POST", body=None):
    try:
        async with session.request(method, url, json=body) as response:
            return await response.text()
    except Exception as e:
        return f"Error: {e}"

async def send_multiple_requests():
    urls = [
        "http://192.168.1.14:9948/modsecurity/test",
        # "http://192.168.1.14:9948/modsecurity/test",
        # "http://192.168.1.14:9948/modsecurity/test",
        # "http://192.168.1.14:9948/modsecurity/test",
        # "http://192.168.1.14:9948/modsecurity/test",
        # "http://192.168.1.14:9948/modsecurity/test",
        # "http://192.168.1.14:9948/modsecurity/test"
    ]
    
    # Dữ liệu gửi kèm theo mỗi request
    bodies = [
        {
        "data": {
                "_ip_root_cause_": "192.168.1.2",
                "_message_": "Detected from default-xss-analyzer analyzer",
                "by_rule": "(?i)<.*?(=|:|>)(.*?['\"]|>|.*?)",
                "field_name": "request_body",
                "field_value": "\"`'><script>ï¿®javascript:alert(1)</script>"
            },
            "reason": "Success: Potential Cross Site Scripting detected",
            "type": "xss_analyzer"
        },
        # {
        # "data": {
        #         "_ip_root_cause_": "",
        #         "_message_": "Detected from default-xss-analyzer analyzer",
        #         "by_rule": "(?i)<.*?(=|:|>)(.*?['\"]|>|.*?)",
        #         "field_name": "request_body",
        #         "field_value": "\"`'><script>ï¿®javascript:alert(1)</script>"
        #     },
        #     "reason": "Success: Potential Cross Site Scripting detected",
        #     "type": "xss_analyzer"
        # },
        # {
        # "data": {
        #         "_ip_root_cause_": "",
        #         "_message_": "Detected from default-xss-analyzer analyzer",
        #         "by_rule": "",
        #         "field_name": "request_body",
        #         "field_value": "\"`'><script>ï¿®javascript:alert(1)</script>"
        #     },
        #     "reason": "Success: Potential Cross Site Scripting detected",
        #     "type": "xss_analyzer"
        # },
        # {
        # "data": {
        #         "_ip_root_cause_": "192.168.1.2",
        #         "_message_": "Detected from default-xss-analyzer analyzer",
        #         "by_rule": "",
        #         "field_name": "request_body",
        #         "field_value": ""
        #     },
        #     "reason": "Success: Potential Cross Site Scripting detected",
        #     "type": "xss_analyzer"
        # },
        # {
        # "data": {
        #         "_ip_root_cause_": "192.168.1.2",
        #         "_message_": "Detected from default-xss-analyzer analyzer",
        #         "by_rule": "(?i)<.*?(=|:|>)(.*?['\"]|>|.*?)",
        #         "field_name": "request_body",
        #         "field_value": ""
        #     },
        #     "reason": "Success: Potential Cross Site Scripting detected",
        #     "type": "xss_analyzer"
        # },
        # {
        # "data": {
        #         "_ip_root_cause_": "",
        #         "_message_": "Detected from default-xss-analyzer analyzer",
        #         "by_rule": "(?i)<.*?(=|:|>)(.*?['\"]|>|.*?)",
        #         "field_name": "request_body",
        #         "field_value": ""
        #     },
        #     "reason": "Success: Potential Cross Site Scripting detected",
        #     "type": "xss_analyzer"
        # },
        # {
        # "data": {
        #         "_ip_root_cause_": "192.168.1.2",
        #         "_message_": "Detected from default-xss-analyzer analyzer",
        #         "by_rule": "",
        #         "field_name": "request_body",
        #         "field_value": "\"`'><script>ï¿®javascript:alert(1)</script>"
        #     },
        #     "reason": "Success: Potential Cross Site Scripting detected",
        #     "type": "xss_analyzer"
        # }
    ]

    async with aiohttp.ClientSession() as session:
        tasks = [
            send_request(url, session, method="POST", body=body) 
            for url, body in zip(urls, bodies)
        ]
        results = await asyncio.gather(*tasks)
        for i, result in enumerate(results, 1):
            print(f"Response {i}:\n{result}")

# Chạy chương trình
asyncio.run(send_multiple_requests())
