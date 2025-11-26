#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🚀 ApexRecon - The Next Gen Recon Tool
Author: Saleh
Features: Rich UI, WAF Detection, Discord Alerts, HTML Reporting.
"""

import os
import sys
import subprocess
import argparse
import requests
import shutil
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.style import Style

# إعداد الكونسول الجميل
console = Console()

class ApexRecon:
    def __init__(self, target, discord_webhook=None):
        self.target = target
        self.discord_webhook = discord_webhook
        self.timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
        self.output_dir = f"ApexResults/{self.target}_{self.timestamp}"
        
        # الملفات
        self.subs_file = os.path.join(self.output_dir, "subdomains.txt")
        self.live_file = os.path.join(self.output_dir, "live_hosts.txt")
        self.vuln_file = os.path.join(self.output_dir, "nuclei_vulns.txt")
        self.html_report = os.path.join(self.output_dir, "report.html")

    def print_banner(self):
        console.print(Panel.fit(
            f"[bold cyan]🎯 Target:[/bold cyan] [bold white]{self.target}[/bold white]\n"
            f"[bold cyan]📂 Output:[/bold cyan] [bold yellow]{self.output_dir}[/bold yellow]\n"
            f"[bold cyan]🕒 Time:[/bold cyan] [bold white]{self.timestamp}[/bold white]",
            title="[bold green]🚀 ApexRecon v2.0[/bold green]",
            subtitle="[italic]Automated Intelligent Recon[/italic]"
        ))

    def setup_dirs(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def check_waf(self):
        """ميزة ذكية: فحص هل الموقع محمي بـ WAF قبل الهجوم"""
        console.print(f"\n[bold yellow][*] Checking for WAF (Web Application Firewall)...[/bold yellow]")
        try:
            r = requests.get(f"http://{self.target}", timeout=5)
            headers = r.headers
            waf_name = "None"
            
            if "CF-RAY" in headers: waf_name = "Cloudflare"
            elif "Server" in headers and "Akamai" in headers["Server"]: waf_name = "Akamai"
            elif "X-Sucuri-ID" in headers: waf_name = "Sucuri"
            
            if waf_name != "None":
                console.print(f"[bold red][!] WAF DETECTED: {waf_name}[/bold red]")
                console.print("[dim]⚠️  Nuclei scan will be slower to avoid bans.[/dim]")
                return True
            else:
                console.print(f"[bold green][√] No obvious WAF detected. Going Full Speed![/bold green]")
                return False
        except:
            console.print("[dim][!] Could not reach target main page.[/dim]")
            return False

    def run_command(self, cmd):
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass

    def start_recon(self):
        self.setup_dirs()
        self.print_banner()
        
        has_waf = self.check_waf()

        # 1. Subdomain Hunting
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            task1 = progress.add_task("[cyan]Harvesting Subdomains...", total=None)
            
            # Subfinder
            self.run_command(f"subfinder -d {self.target} -silent > {self.output_dir}/raw_subs.txt")
            # Assetfinder
            self.run_command(f"assetfinder --subs-only {self.target} >> {self.output_dir}/raw_subs.txt")
            
            # Cleaning
            unique_subs = set()
            try:
                with open(f"{self.output_dir}/raw_subs.txt", "r") as f:
                    unique_subs = set(f.read().splitlines())
            except: pass
            
            with open(self.subs_file, "w") as f:
                f.write("\n".join(unique_subs))
                
            progress.stop()

        console.print(f"[bold green][√] Found {len(unique_subs)} unique subdomains.[/bold green]")

        # 2. Live Probing (Httpx)
        if len(unique_subs) > 0:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task("[magenta]Probing Live Hosts (Httpx)...", total=None)
                # حفظ المخرجات كملف نصي عادي وكـ JSON للتقرير
                self.run_command(f"httpx -l {self.subs_file} -title -tech-detect -status-code -silent -o {self.live_file}")
            
            # عد الأحياء
            try:
                with open(self.live_file, "r") as f:
                    live_count = len(f.readlines())
            except: live_count = 0
            console.print(f"[bold green][√] Found {live_count} live hosts.[/bold green]")
        else:
            console.print("[bold red][!] No subdomains found. Exiting.[/bold red]")
            return

        # 3. Vulnerability Scanning (Nuclei)
        if live_count > 0:
            console.print(f"\n[bold yellow][*] Starting Nuclei Scan (This is the heavy part)...[/bold yellow]")
            
            # استخراج الروابط فقط من نتائج Httpx
            urls_file = os.path.join(self.output_dir, "urls.txt")
            with open(self.live_file, "r") as f:
                urls = [line.split()[0] for line in f.readlines()]
            with open(urls_file, "w") as f:
                f.write("\n".join(urls))

            # تعديل سرعة الفحص بناء على الـ WAF
            rate_limit = "-rl 150" if not has_waf else "-rl 50"
            
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=False) as progress:
                progress.add_task("[red]Firing Nuclei Engine...", total=None)
                self.run_command(f"nuclei -l {urls_file} -t nuclei-templates -severity critical,high,medium {rate_limit} -silent -o {self.vuln_file}")

            # التحقق من الثغرات
            vuln_count = 0
            if os.path.exists(self.vuln_file):
                with open(self.vuln_file, "r") as f:
                    vuln_count = len(f.readlines())

            if vuln_count > 0:
                console.print(f"[bold red on white]🚨 DANGER: Found {vuln_count} Vulnerabilities! Check Report![/bold red on white]")
                self.send_discord(f"🚨 **ApexRecon Alert:** Found {vuln_count} vulnerabilities on {self.target}!")
            else:
                console.print("[bold green][√] No Critical/High vulnerabilities found.[/bold green]")
                self.send_discord(f"✅ **ApexRecon:** Scan finished on {self.target}. Clean (so far).")

        self.generate_html_report(len(unique_subs), live_count, vuln_count)

    def generate_html_report(self, subs, live, vulns):
        """ميزة فريدة: توليد تقرير HTML بسيط"""
        html_content = f"""
        <html>
        <head>
            <title>ApexRecon - {self.target}</title>
            <style>
                body {{ font-family: Arial; background: #111; color: #fff; padding: 20px; }}
                .card {{ background: #222; padding: 20px; margin: 10px; border-radius: 8px; border-left: 5px solid #00ff41; }}
                h1 {{ color: #00ff41; }}
                .stat {{ font-size: 20px; }}
            </style>
        </head>
        <body>
            <h1>🚀 ApexRecon Report: {self.target}</h1>
            <p>Date: {self.timestamp}</p>
            <div class="card">
                <h3>Stats</h3>
                <p class="stat">🌐 Subdomains: {subs}</p>
                <p class="stat">🟢 Live Hosts: {live}</p>
                <p class="stat">🔥 Vulnerabilities: {vulns}</p>
            </div>
            <div class="card">
                <h3>Files</h3>
                <p>📂 <a href="live_hosts.txt">Live Hosts List</a></p>
                <p>📂 <a href="nuclei_vulns.txt">Vulnerabilities List</a></p>
            </div>
        </body>
        </html>
        """
        with open(self.html_report, "w") as f:
            f.write(html_content)
        console.print(f"\n[bold white]📄 HTML Report Generated:[/bold white] [underline]{self.html_report}[/underline]")

    def send_discord(self, message):
        """ميزة فريدة: إرسال تنبيه للديسكورد"""
        if self.discord_webhook:
            data = {"content": message}
            try:
                requests.post(self.discord_webhook, json=data)
            except: pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ApexRecon")
    parser.add_argument("-t", "--target", required=True, help="Target Domain")
    parser.add_argument("-w", "--webhook", help="Discord Webhook URL (Optional)")
    args = parser.parse_args()

    try:
        scanner = ApexRecon(args.target, args.webhook)
        scanner.start_recon()
    except KeyboardInterrupt:
        console.print("\n[bold red]Aborted![/bold red]")