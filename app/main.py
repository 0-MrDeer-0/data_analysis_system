from rich.console import Console
from rich.align import Align
from rich.table import Table
from rich.panel import Panel
from rich.box import ROUNDED

console = Console()


def show_banner():
    banner = """ ____                 ____  _        _   
|  _ \  ___  ___ _ __/ ___|| |_ __ _| |_ 
| | | || _ \| _ \ '__\___ \| __/ _` | __|
| |_| |  __/  __/ |   ___) | || (_| | |_ 
|____/ \___|\___|_|  |____/ \__\__,_|\__|
"""
    centered_banner = Align.center(banner, vertical="middle")
    console.print(centered_banner, style="bold green")


def show_menu(menu_name="user_actions"):
    menus = {
        "auth": {
            "items": [
                "[1] 🔐 Sign in",
                "[2] 📝 Sign up",
                "[3] ♻️  Reset password",
                "[0]🚪 Exit",
            ],
            "header": "User Authentication Menu",
        },
        "user_actions": {
            "items": [
                "[1] 📋 Display data",
                "[2] 📊 Statistical analysis",
                "[3] 🔎 Data search",
                "[0]🚪 Exit",
            ],
            "header": "Data Management Menu",
        },
    }
    menu_data = menus.get(menu_name, {})
    menu_items = menu_data.get("items", [])
    header_menu = menu_data.get("header", "Menu")
    if not menu_items:
        show_message("error", "Menu not found!")
        return None
    console.print(Align.center(header_menu, style="bold"))
    table = Table(
        show_header=False, expand=False, box=ROUNDED, pad_edge=True, style="dim grey70"
    )
    table.add_row(*menu_items)
    console.print(Align.center(table, vertical="middle"))
    return input("\n 🛎️  Enter your number choice: [ ]\033[12;32H")


def show_header(menu_name="user_actions"):
    console.clear()
    show_banner()
    choice = show_menu(menu_name)
    return choice


def show_message(type, message):
    panel_types = {
        "error": {"icon": "❌", "title": "[bold]Error[/bold]", "color": "#FF6F61"},
        "warning": {"icon": "⚠️", "title": "[bold]Warning[/bold]", "color": "#FFA726"},
        "success": {"icon": "🎉", "title": "[bold]Success[/bold]", "color": "#66BB6A"},
        "info": {"icon": "ℹ️", "title": "[bold]Info[/bold]", "color": "#42A5F5"},
    }
    default_type = "info"
    selected_type = panel_types.get(type, panel_types[default_type])
    console.print("\n")
    console.print(
        Panel(
            f"{message}",
            title=f"{selected_type['icon']}  {selected_type['title']}",
            style=selected_type["color"],
        )
    )
    input(" Press enter key to continue ...")
