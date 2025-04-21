import asyncio
import aiohttp
import logging
import aiodns
import sys
from bs4 import BeautifulSoup  # 用於解析 HTML 表單

# 定義終端機輸出顏色代碼
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# 初始化全域變數
PAYLOADS = {
    "SQL Injection": "' OR '1'='1",
    "XSS": "<script>alert('XSS')</script>"
}
VISITED = set()

# 獲取表單的函式
async def get_forms(session, url):
    try:
        async with session.get(url) as response:
            html = await response.text()
            soup = BeautifulSoup(html, "html.parser")
            forms = soup.find_all("form")
            return forms
    except Exception as e:
        logging.error(f"無法獲取表單：{str(e)}")
        return []

# 掃描表單的函式
async def scan_form(session, url, form, vuln_name, payload):
    try:
        action = form.get("action")
        if not action:  # 如果 action 為 None，設置為空字串
            action = ""
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        form_data = {inp.get("name"): payload for inp in inputs if inp.get("name")}

        # 構造目標 URL
        target_url = url if action.startswith("http") else f"{url.rstrip('/')}/{action.lstrip('/')}"
        if method == "post":
            async with session.post(target_url, data=form_data) as response:
                text = await response.text()
        else:
            async with session.get(target_url, params=form_data) as response:
                text = await response.text()

        # 檢查回應是否包含漏洞特徵
        if payload.lower() in text.lower():
            print(f"{RED}[!] 發現潛在 {vuln_name} 漏洞於 {url} (載荷：{payload}){RESET}")
            logging.warning(f"潛在 {vuln_name} 漏洞於 {url}，載荷：{payload}")
        else:
            print(f"{GREEN}[OK] {vuln_name} 測試通過於 {url}{RESET}")
            logging.info(f"{vuln_name} 測試通過於 {url}")
    except Exception as e:
        print(f"{RED}[x] 測試 {vuln_name} 於 {url} 失敗：{str(e)}{RESET}")
        logging.error(f"測試 {vuln_name} 於 {url} 失敗：{str(e)}")

# 驗證 URL 是否有效
def is_valid_url(url):
    return url and (url.startswith("http://") or url.startswith("https://"))

# 獲取連結的函式
async def get_links(session, url):
    try:
        async with session.get(url) as response:
            html = await response.text()
            soup = BeautifulSoup(html, "html.parser")
            links = [a.get("href") for a in soup.find_all("a", href=True)]
            # 過濾掉 None 值並返回完整的 URL
            return [link for link in links if link and is_valid_url(link)]
    except Exception as e:
        logging.error(f"無法獲取連結：{str(e)}")
        return []

# 掃描單一頁面的函式
async def scan_page(session, url):
    print(f"{CYAN}[*] 掃描：{url}{RESET}")
    logging.info(f"開始掃描：{url}")
    forms = await get_forms(session, url)
    for form in forms:
        for vuln, payload in PAYLOADS.items():
            await scan_form(session, url, form, vuln, payload)
            await asyncio.sleep(0.5)  # 限制掃描速率

# 非同步爬取與掃描的主函式
async def crawl_and_scan(start_url, depth=2):
    if not is_valid_url(start_url):
        print(f"{RED}[x] 無效URL：{start_url}{RESET}")
        logging.error(f"無效URL：{start_url}")
        return

    queue = [(start_url, 0)]
    VISITED.add(start_url)

    resolver = aiodns.DNSResolver()
    connector = aiohttp.TCPConnector()

    async with aiohttp.ClientSession(connector=connector) as session:
        while queue:
            tasks = []
            next_queue = []
            for url, level in queue:
                if level >= depth:
                    continue
                tasks.append(scan_page(session, url))
                links = await get_links(session, url)
                next_queue.extend((link, level + 1) for link in links if link not in VISITED)
                VISITED.update(link for link, _ in next_queue)
            if tasks:
                await asyncio.gather(*tasks)
            queue = next_queue
            await asyncio.sleep(1)

# 主程式入口
if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    logging.basicConfig(level=logging.INFO, filename="vuln_scanner.log", filemode="w",
                        format="%(asctime)s - %(levelname)s - %(message)s")
    print(f"{CYAN}=== VulnHunterAI 終端機掃描器 ==={RESET}")
    target = input("輸入目標URL（含http/https）：").strip()
    try:
        asyncio.run(crawl_and_scan(target))
        print(f"{GREEN}[+] 掃描完成！結果已儲存至日誌檔案{RESET}")
    except KeyboardInterrupt:
        print(f"{YELLOW}[-] 用戶中斷掃描{RESET}")
        logging.info("用戶中斷掃描")
    except Exception as e:
        print(f"{RED}[x] 掃描失敗：{str(e)}{RESET}")
        logging.error(f"掃描失敗：{str(e)}")