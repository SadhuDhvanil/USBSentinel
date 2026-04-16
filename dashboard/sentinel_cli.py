#!/usr/bin/env python3
"""
USBSentinel CLI Dashboard
Review quarantined files — Allow or Deny at your own risk.
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from quarantine.quarantine_manager import (
    list_quarantine, update_status, delete_from_quarantine
)

console = Console()

def load_settings():
    with open("config/settings.json") as f:
        return json.load(f)


def color_verdict(verdict):
    colors = {
        "MALICIOUS":   "bold red",
        "SUSPICIOUS":  "bold yellow",
        "CLEAN":       "bold green",
        "quarantined": "yellow",
        "allowed":     "green",
        "denied":      "red"
    }
    return colors.get(verdict, "white")


def show_banner():
    console.print(Panel(
        Text("USBSentinel — Quarantine Dashboard", justify="center", style="bold cyan"),
        subtitle="Review and manage quarantined files"
    ))


def show_table(items):
    if not items:
        console.print("\n[green]✓ Quarantine is empty. No threats found.[/green]\n")
        return False

    table = Table(show_lines=True, header_style="bold cyan")
    table.add_column("#",         width=4,  style="dim")
    table.add_column("Filename",  width=28, style="cyan")
    table.add_column("Verdict",   width=12)
    table.add_column("Score",     width=7)
    table.add_column("Status",    width=12)
    table.add_column("Timestamp", width=18)
    table.add_column("Reason",    width=35)

    for i, item in enumerate(items):
        verdict_style = color_verdict(item.get("verdict", ""))
        status_style  = color_verdict(item.get("status", ""))
        table.add_row(
            str(i),
            item.get("filename", "unknown"),
            f"[{verdict_style}]{item.get('verdict', '?')}[/{verdict_style}]",
            str(item.get("score", "?")),
            f"[{status_style}]{item.get('status', '?').upper()}[/{status_style}]",
            item.get("timestamp", ""),
            item.get("reason", "")[:50]
        )

    console.print(table)
    return True


def file_detail(item):
    console.print(Panel(
        f"[bold]File:[/bold]     {item.get('original_path', '?')}\n"
        f"[bold]Hash:[/bold]     {item.get('hash', '?')}\n"
        f"[bold]Verdict:[/bold]  {item.get('verdict', '?')}\n"
        f"[bold]Score:[/bold]    {item.get('score', '?')} / 100\n"
        f"[bold]Reason:[/bold]   {item.get('reason', '?')}\n"
        f"[bold]Status:[/bold]   {item.get('status', '?')}\n"
        f"[bold]Quarantine:[/bold] {item.get('quarantine_path', '?')}",
        title="File Details",
        border_style="yellow"
    ))


def main():
    show_banner()
    settings        = load_settings()
    quarantine_store = settings["quarantine_path"]

    while True:
        items = list_quarantine(quarantine_store)
        has_items = show_table(items)

        console.print("\n[bold]Options:[/bold]")
        console.print("  [cyan]r[/cyan]  — Refresh list")
        console.print("  [cyan]#[/cyan]  — Enter file number to review")
        console.print("  [cyan]q[/cyan]  — Quit\n")
        console.print("Choice: ", end="")

        try:
            choice = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if choice == "q":
            console.print("[dim]Exiting USBSentinel dashboard.[/dim]")
            break

        if choice == "r" or choice == "":
            continue

        try:
            idx  = int(choice)
            item = items[idx]
        except (ValueError, IndexError):
            console.print("[red]Invalid choice. Enter a number from the # column.[/red]")
            continue

        file_detail(item)

        console.print("\n[bold red]⚠  Warning:[/bold red] "
                      "Allowing a quarantined file is entirely at your own risk.")
        console.print("Action: [A]llow  [D]eny  [X] Delete permanently  [C]ancel: ", end="")

        try:
            action = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        qpath = item.get("quarantine_path", "")

        if action == "a":
            update_status(qpath, "allowed")
            console.print(
                "[green]✓ Marked as ALLOWED.[/green] "
                "File stays in quarantine store but flagged as user-approved."
            )
        elif action == "d":
            update_status(qpath, "denied")
            console.print("[red]✗ Marked as DENIED (confirmed threat).[/red]")
        elif action == "x":
            console.print(
                "[bold red]Permanently delete this file? "
                "This cannot be undone. (yes/no): [/bold red]", end=""
            )
            try:
                confirm = input().strip().lower()
            except (KeyboardInterrupt, EOFError):
                continue
            if confirm == "yes":
                delete_from_quarantine(qpath)
                console.print("[red]✓ File permanently deleted.[/red]")
            else:
                console.print("[dim]Deletion cancelled.[/dim]")
        else:
            console.print("[dim]Cancelled.[/dim]")

        console.print()


if __name__ == "__main__":
    main()
