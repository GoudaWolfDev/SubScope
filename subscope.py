#!/usr/bin/env python3
"""
==============================================================================
 SubScope - Asset Recon & Status Filter Utility
 Developer: goudawolfdev | D33P-X (Gouda Nasralla)
 Description: High-performance, multithreaded web asset filter & live status 
              checker designed for asset management and reconnaissance.
==============================================================================
"""

import argparse
import json
import os
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any

import requests
import urllib3
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.table import Table
from rich.panel import Panel

# تعطيل تحذيرات شهادات SSL غير الموثوقة
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

DEV_INFO = "Developer: goudawolfdev | D33P-X (Gouda Nasralla)"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# (وقت الاتصال بالثواني، وقت قراءة البيانات بالثواني)
FAST_TIMEOUT = (2, 3)
file_lock = threading.Lock()

CATEGORIES = {
    "200 OK": "[bold green]200 OK[/bold green]",
    "Redirect": "[bold yellow]Redirect[/bold yellow]",
    "Protected": "[bold magenta]Protected (401/403)[/bold magenta]",
    "404 Not Found": "[bold blue]404 Not Found[/bold blue]",
    "Server Error": "[bold red]5xx Server Error[/bold red]",
    "Offline": "[dim red]Offline / Unreachable[/dim red]",
    "Other": "[white]Other[/white]"
}

def categorize_status(code: int) -> str:
    if code == 200:
        return "200 OK"
    elif code in (301, 302, 307, 308):
        return "Redirect"
    elif code in (401, 403):
        return "Protected"
    elif code == 404:
        return "404 Not Found"
    elif 500 <= code <= 599:
        return "Server Error"
    elif code == 0:
        return "Offline"
    return "Other"

def quick_dns_check(domain: str, timeout: float = 1.0) -> bool:
    """فحص سريع لـ DNS للتحقق من وجود IP وتفادي تعليق الـ Threads على الدومينات المعطلة."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.timeout, Exception):
        return False

def check_target(domain: str) -> Dict[str, Any]:
    domain = domain.strip()
    
    # 1. التحقق السريع عبر DNS
    if not quick_dns_check(domain):
        return {"domain": domain, "url": f"http://{domain}", "status": 0, "category": "Offline"}

    urls = [f"https://{domain}", f"http://{domain}"]

    for url in urls:
        try:
            # محاولة طلب HEAD السريع
            r = requests.head(url, headers=HEADERS, timeout=FAST_TIMEOUT, verify=False, allow_redirects=False)
            status = r.status_code
            return {"domain": domain, "url": url, "status": status, "category": categorize_status(status)}
        except requests.exceptions.RequestException:
            try:
                # محاولة طلب GET في حالة حظر طلبات HEAD
                r = requests.get(url, headers=HEADERS, timeout=FAST_TIMEOUT, verify=False, allow_redirects=False, stream=True)
                status = r.status_code
                return {"domain": domain, "url": url, "status": status, "category": categorize_status(status)}
            except requests.exceptions.RequestException:
                continue

    return {"domain": domain, "url": f"http://{domain}", "status": 0, "category": "Offline"}

def process_worker(domain: str, results_list: List[Dict[str, Any]], progress, task_id):
    res = check_target(domain)
    with file_lock:
        results_list.append(res)
    progress.advance(task_id)

def save_report_text(output_path: str, results: List[Dict[str, Any]]):
    grouped = {}
    for r in results:
        cat = r["category"]
        grouped.setdefault(cat, []).append(r)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=" * 75 + "\n")
        f.write("                   SUBSCOPE - ASSET SCANNER LIVE RESULTS\n")
        f.write(f"                   {DEV_INFO}\n")
        f.write("=" * 75 + "\n\n")

        for cat, items in sorted(grouped.items()):
            f.write(f"--- [ {cat.upper()} ({len(items)}) ] ---\n")
            for item in items:
                status_str = str(item['status']) if item['status'] != 0 else "OFFLINE"
                f.write(f"  - [{status_str:<5}] {item['domain']:<35} ({item['url']})\n")
            f.write("\n")

def save_report_json(output_path: str, results: List[Dict[str, Any]]):
    data = {
        "tool": "SubScope",
        "developer": "goudawolfdev | D33P-X (Gouda Nasralla)",
        "results": results
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"SubScope - High-performance asset status filter. Developed by {DEV_INFO}"
    )
    parser.add_argument("-i", "--input", required=True, help="Path to input domains file.")
    parser.add_argument("-o", "--output", required=True, help="Path to save output report.")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of concurrent threads (default: 30).")
    parser.add_argument("--json", action="store_true", help="Export results in JSON format instead of text.")
    return parser.parse_args()

def main():
    args = parse_args()

    # شعار الأداة واسم المطور
    console.print(Panel.fit(
        f"[bold cyan]SubScope[/bold cyan]\n"
        f"[dim]High-Speed Recon & Asset Status Filter[/dim]\n"
        f"[bold yellow]{DEV_INFO}[/bold yellow]",
        border_style="cyan"
    ))

    if not os.path.exists(args.input):
        console.print(f"[bold red][!] Error:[/bold red] Input file '{args.input}' does not exist.")
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8") as f:
        domains = sorted(set(line.strip() for line in f if line.strip()))

    console.print(f"[bold green][+][/bold green] Loaded [bold white]{len(domains)}[/bold white] unique domains.")
    console.print(f"[bold green][+][/bold green] Running scan using [bold white]{args.threads}[/bold white] threads...\n")

    results = []

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Scanning domains...", total=len(domains))
            
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                for d in domains:
                    executor.submit(process_worker, d, results, progress, task)

    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan interrupted by user (Ctrl+C). Saving partial results...[/bold red]")

    # حفظ النتائج سواء اكتمل الفحص أو تم إنهاؤه مبكراً
    if args.json:
        save_report_json(args.output, results)
    else:
        save_report_text(args.output, results)

    # عرض جدول الملخص النهائي
    table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="dim")
    table.add_column("Count", justify="right")

    summary_counts = {}
    for r in results:
        summary_counts[r["category"]] = summary_counts.get(r["category"], 0) + 1

    for cat, color_tag in CATEGORIES.items():
        count = summary_counts.get(cat, 0)
        if count > 0:
            table.add_row(color_tag, str(count))

    console.print("\n")
    console.print(table)
    console.print(f"\n[bold green][✔] Finished![/bold green] Results saved to: [bold underline]{args.output}[/bold underline]\n")

if __name__ == "__main__":
    main()