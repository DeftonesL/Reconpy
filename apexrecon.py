#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🚀 ApexRecon v2.2 - Ultimate Recon Framework
Author: Saleh
Updates: List support, Argument flexibility, Speed control.
"""

import os
import sys
import subprocess
import argparse
import requests
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class ApexRecon:
    def __init__(self, target, args):
        self.target = target
        self.args = args
        self.timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
        
        base_dir = self.args.output if self.args.output else "ApexResults"
        self.output_dir = os.path.join(base_dir, f"{self.target}_{self.timestamp}")
        
        self.subs_file = os.path.join(self.output_dir, "subdomains.txt")
        self.live_file = os.path.join(self.output_dir, "live_hosts.txt")
        self.vuln_file = os.path.join(self.output_dir, "nuclei_vulns.txt")
        self.html_report = os.path.join(self.output_dir, "report.html")

    def print_banner(self):
        console.print(Panel.fit(
            f"[bold cyan]🎯 Target:[/bold cyan] [white]{self.target}[/white]\n"
            f"[bold cyan]⚡ Threads:[/bold cyan] [yellow]{self.args.threads}[/yellow] | "
            f"[bold cyan]🚀 Rate Limit:[/bold cyan] [yellow]{self.args.rate_limit}[/yellow]\n"
            f"[bold cyan]📂 Output:[/bold cyan] [white]{self.output_dir}[/white]",
            title="[bold green]🚀 ApexRecon v2.2[/bold green]",
            subtitle="[italic]Flexibility & Power Update[/italic]"
        ))

    def setup_dirs(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def run_command(self, cmd):
        try:
            stdout_setting = None if self.args.verbose else subprocess.DEVNULL
            stderr_setting = None if self.args.verbose else subprocess.DEVNULL
            subprocess.run(cmd, shell=True, check=True, stdout=stdout_setting, stderr=stderr_setting)
        except subprocess.CalledProcessError:
            pass

    def check_waf(self):
        try:
            r = requests.get(f"http://{self.target}", timeout=5)
            headers = r.headers
            if "CF-RAY" in headers: return "Cloudflare"
            if "Server" in headers and "Akamai" in headers["Server"]: return "Akamai"
            if "X-Sucuri-ID" in headers: return "Sucuri"
        except: pass
        return None

    def start_recon(self):
        self.setup_dirs()
        self.print_banner()

        unique_subs = set()
        live_count = 0
        vuln_count = 0

        if not self.args.no_subs:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task("[cyan]Harvesting Subdomains...", total=None)
                
                self.run_command(f"subfinder -d {self.target} -silent -t {self.args.threads} > {self.output_dir}/raw_subs.txt")
                self.run_command(f"assetfinder --subs-only {self.target} >> {self.output_dir}/raw_subs.txt")
                
                if os.path.exists(f"{self.output_dir}/raw_subs.txt"):
                    with open(f"{self.output_dir}/raw_subs.txt", "r") as f:
                        unique_subs = set(f.read().splitlines())
                    with open(self.subs_file, "w") as f:
                        f.write("\n".join(unique_subs))

            console.print(f"[bold green][√] Found {len(unique_subs)} unique subdomains.[/bold green]")
        else:
            console.print("[yellow][!] Skipping Subdomain Discovery (--no-subs). Assuming target is a host.[/yellow]")
            with open(self.subs_file, "w") as f: f.write(self.target)
            unique_subs = {self.target}

        if len(unique_subs) > 0:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
                progress.add_task("[magenta]Probing Live Hosts (Httpx)...", total=None)
                self.run_command(f"httpx -l {self.subs_file} -title -tech-detect -status-code -silent -threads {self.args.threads} -o {self.live_file}")
            
            if os.path.exists(self.live_file):
                with open(self.live_file, "r") as f: live_count = len(f.readlines())
            console.print(f"[bold green][√] Found {live_count} live hosts.[/bold green]")
        else:
            console.print("[red][!] No targets to probe.[/red]")

        if not self.args.no_vuln and live_count > 0:
            waf_name = self.check_waf()
            if waf_name:
                console.print(f"[bold red][!] WAF Detected: {waf_name}. Reducing speed automatically.[/bold red]")
                current_rate = 50 
            else:
                current_rate = self.args.rate_limit

            console.print(f"[yellow][*] Starting Nuclei (Rate Limit: {current_rate})...[/yellow]")
            
            urls_file = os.path.join(self.output_dir, "urls.txt")
            if os.path.exists(self.live_file):
                with open(self.live_file, "r") as f:
                    urls = [line.split()[0] for line in f.readlines()]
                with open(urls_file, "w") as f: f.write("\n".join(urls))

            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=False) as progress:
                progress.add_task("[red]Firing Nuclei Engine...", total=None)
                self.run_command(f"nuclei -l {urls_file} -t nuclei-templates -severity critical,high,medium -rl {current_rate} -silent -o {self.vuln_file}")

            if os.path.exists(self.vuln_file):
                with open(self.vuln_file, "r") as f: vuln_count = len(f.readlines())
            
            if vuln_count > 0:
                console.print(f"[bold red on white]🚨 DANGER: Found {vuln_count} Vulnerabilities![/bold red on white]")
                self.send_discord(f"🚨 **ApexRecon Alert:** Found {vuln_count} vulnerabilities on {self.target}!")
            else:
                console.print("[green][√] Clean scan. No Critical/High vulns.[/green]")
                self.send_discord(f"✅ **ApexRecon:** Scan clean for {self.target}.")
        
        elif self.args.no_vuln:
            console.print("[yellow][!] Skipping Vulnerability Scan (--no-vuln).[/yellow]")

        self.generate_report(len(unique_subs), live_count, vuln_count)

    def generate_report(self, subs, live, vulns):
        html_content = f"""<html><body style='background:#111;color:#fff;font-family:sans-serif;padding:20px'>
        <h1 style='color:#0f0'>ApexRecon Report: {self.target}</h1>
        <div style='background:#222;padding:20px;border-radius:10px;border-left:5px solid #0f0'>
        <h3>Stats</h3><p>🌐 Subdomains: {subs}</p><p>🟢 Live Hosts: {live}</p><p>🔥 Vulns: {vulns}</p>
        </div></body></html>"""
        try:
            with open(self.html_report, "w") as f: f.write(html_content)
            console.print(f"\n[bold white]📄 HTML Report:[/bold white] [underline]{self.html_report}[/underline]")
        except: pass

    def send_discord(self, msg):
        if self.args.webhook:
            try: requests.post(self.args.webhook, json={"content": msg})
            except: pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ApexRecon v2.2 - Advanced Recon Framework")
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Single Target Domain (e.g., tesla.com)")
    target_group.add_argument("-l", "--list", help="File containing list of targets")

    parser.add_argument("-o", "--output", help="Custom Output Directory", default="ApexResults")
    parser.add_argument("-w", "--webhook", help="Discord Webhook URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show tool output (Debug mode)")
    
    parser.add_argument("--threads", type=int, default=40, help="Number of threads for Subfinder/Httpx (Default: 40)")
    parser.add_argument("--rate-limit", type=int, default=150, help="Rate limit for Nuclei (Default: 150)")

    parser.add_argument("--no-subs", action="store_true", help="Skip subdomain enumeration (Treat target as host)")
    parser.add_argument("--no-vuln", action="store_true", help="Skip vulnerability scanning (Nuclei)")

    args = parser.parse_args()

    console.print("[bold green]🚀 ApexRecon v2.2 Initialized...[/bold green]")

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        if os.path.exists(args.list):
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
            console.print(f"[bold cyan][*] Loaded {len(targets)} targets from list.[/bold cyan]")
        else:
            console.print(f"[bold red][!] File not found: {args.list}[/bold red]")
            sys.exit(1)

    for target in targets:
        try:
            scanner = ApexRecon(target, args)
            scanner.start_recon()
            console.print(f"[dim]{'-'*50}[/dim]\n")
        except KeyboardInterrupt:
            console.print("\n[bold red]Aborted by user![/bold red]")
            sys.exit(0)
