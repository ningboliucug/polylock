import subprocess
import time
import sys

# 我们要监控的两个核心容器名称
containers = ["sat-node", "term-node"]

# 初始化峰值字典
peaks = {c: {"cpu": 0.0, "mem": 0.0} for c in containers}

def parse_mem_to_mb(mem_str):
    """将 Docker 的内存字符串 (例如 '45.5MiB', '1.2GiB') 统一转换为 MB"""
    mem_str = mem_str.upper().strip()
    try:
        if 'GIB' in mem_str: return float(mem_str.replace('GIB', '')) * 1024
        if 'MIB' in mem_str: return float(mem_str.replace('MIB', ''))
        if 'KIB' in mem_str: return float(mem_str.replace('KIB', '')) / 1024
        if 'B' in mem_str:   return float(mem_str.replace('B', '')) / (1024*1024)
    except ValueError:
        return 0.0
    return 0.0

print("==================================================")
print("开始监控卫星端 (sat-node) 和终端 (term-node) 的资源峰值...")
print("请在另一个窗口启动实验 (docker-compose up)。")
print("实验结束后，在此窗口按【Ctrl + C】停止监控并查看最终数据。")
print("==================================================")

try:
    while True:
        try:
            # 调用 docker stats，不阻塞，仅输出指定格式
            out = subprocess.check_output(
                ['docker', 'stats', '--no-stream', '--format', '{{.Name}},{{.CPUPerc}},{{.MemUsage}}', 'sat-node', 'term-node'],
                stderr=subprocess.DEVNULL, 
                universal_newlines=True
            )
            
            # 解析输出行
            for line in out.strip().split('\n'):
                if not line: continue
                parts = line.split(',')
                if len(parts) >= 3:
                    name = parts[0]
                    # 处理 CPU 字符串 (例如 '15.40%')
                    cpu_str = parts[1].replace('%', '')
                    cpu_val = float(cpu_str) if cpu_str.replace('.', '', 1).isdigit() else 0.0
                    
                    # 处理内存字符串 (例如 '45MiB / 512MiB'，我们只要 / 前面的实际使用量)
                    mem_raw = parts[2].split('/')[0]
                    mem_val = parse_mem_to_mb(mem_raw)
                    
                    # 更新峰值
                    if name in peaks:
                        peaks[name]['cpu'] = max(peaks[name]['cpu'], cpu_val)
                        peaks[name]['mem'] = max(peaks[name]['mem'], mem_val)
                        
        except subprocess.CalledProcessError:
            # 容器可能还没启动，忽略报错，继续等待
            pass
            
        # 轮询间隔：0.2秒采集一次，足以捕捉极速突发峰值
        time.sleep(0.2) 

except KeyboardInterrupt:
    print("\n\n==================================================")
    print("监控结束！最终峰值数据提取如下：")
    print("==================================================")
    for c in containers:
        print(f"[{c}]")
        print(f"  -> CPU 峰值:   {peaks[c]['cpu']:.2f} %")
        print(f"  -> 内存峰值: {peaks[c]['mem']:.2f} MB")
    print("==================================================")
    sys.exit(0)
