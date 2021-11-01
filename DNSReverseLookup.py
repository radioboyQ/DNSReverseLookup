from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
from json import dumps
import os.path
import sys
from time import sleep

import click
import dns.zone
import dns.ipv4
import dns.resolver
import dns.reversename
from rich import box
from rich import print
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn
from rich.table import Table


def sort_answers(raw_resp):
    """
    Split out just the Answer section of the request
    """

    answer_bool = False
    resp_list = list()

    for row in str(raw_resp).splitlines():
        if row == ";ANSWER":
            answer_bool = True
        if answer_bool and row != ";AUTHORITY" and row != ";ANSWER":
            resp_list.append(row.split(" ")[-1])
        elif row == ";AUTHORITY":
            answer_bool = False
    return resp_list

def ip_addr_check(ip_addr):
    """
    Function to check if an IP Address is a valid network or host
    """
    try:
        # Check if it's a network
        converted_addr = ip_network(ip_addr, strict=False)
    except ValueError:
        try:
            # check if it's a single host
            converted_addr = ip_address(ip_addr)
        except ValueError:
            raise
    return converted_addr

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

@click.command("dns-reverse-lookup", context_settings=CONTEXT_SETTINGS, )
@click.option("-n", "--nameserver", multiple=True, help=f"Define one or more name servers to look up against",
              show_default=True, default=["127.0.0.1"], type=click.STRING)
@click.option("-a", "--address", help="Address or network to look up. Needs to be CIDR: 192.168.1.1/24 or single host",
              multiple=True)
@click.option("-s", "--silent", is_flag=True, default=False, help="Remove progress bar and configuration table "
                                                                  "from output.")
@click.option("-p", "--port", help="Define DNS server port.", default=53, type=click.IntRange(min=1, max=65535), show_default=True)
@click.option("-j", "--show-json", help="Return a JSON blob instead of a table", is_flag=True, default=False)
@click.option("--rfc-1918", help="Scan all RFC1980 Addresses: 100.64.0.0/10, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. "
                                 "This is additive to any other addresses listed.", is_flag=True, default=False)
@click.pass_context
def main(ctx, nameserver, silent, address, port, show_json, rfc_1918):
    """
    Do reverse lookups against multiple DNS servers within a given address or network range
    """

    verbose = False
    # Make address a list
    address = list(address)
    console = Console()
    addr_list = list()
    output_json_dict = dict()

    # Do a lookup for all RFC 1918 addresses
    if rfc_1918:
        console.print(f"[bold][blink]WARNING![/] This is going to take a [i]long[/] time", justify="center")
        address.extend(["100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])

    # Check if addresses exist. If not, pop a prompt
    if len(address) == 0:
        # Address tuple length is 0
        console.print(f"[bold]Prompt will loop until a blank entry[/bold]")
        while True:
            resp = console.input("IP Address or Network to query for:")
            if len(resp) == 0 and len(addr_list) == 0:
                console.print("- Ya need to enter [i]something[/i]")
            elif len(resp) == 0:
                # Allow loop exit if no input is entered
                break
            else:
                # The response has something in it, try it out
                try:
                    ip_resp = ip_addr_check(resp)
                    addr_list.append(ip_resp)
                except ValueError:
                    console.print(f"The address {resp} wasn't valid. Try again")
    else:
        # If the CLI was used to enter an address, get those into addr_list
        for ip in address:
            try:
                ip_resp = ip_addr_check(ip)
                addr_list.append(ip_resp)
            except ValueError:
                console.print(f"The address {ip} wasn't valid. Skipping")

        # Verify that the address list has something in it
        if len(addr_list) == 0:
            console.print(f"No valid addresses found")
            sys.exit(1)

    # Show the config if not requested to be silent
    if not silent:
        # If silent isn't true, print this table
        status_table = Table(title="Configuration", show_lines=True)
        status_table.add_column("Type", justify="left", style="cyan")
        status_table.add_column("Address", justify="right", style="green")
        if len(nameserver) > 1:
            status_table.add_row("DNS Servers", f"{nameserver}")
        else:
            status_table.add_row("DNS Server", f"{nameserver[0]}")

        if len(addr_list) > 1:
            status_table.add_row("Addresses", f"{addr_list}")
        else:
            status_table.add_row("Address", f"{addr_list[0]}")
        status_table.add_row("DNS Port", f"{port}")


        console.print(status_table, justify="left")

    table = Table(title="Resolved Addresses", box=box.HEAVY_EDGE, show_lines=True)

    table.add_column("Addresses", justify="left")
    table.add_column("Domain Name", justify="center")
    table.add_column("Name Server", justify="right")

    resolver = dns.resolver.Resolver(configure=False)
    resolver.port = port

    # Progress bar nonsense
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed} of {task.total}"),
            console=console,
            transient=True,
    ) as progress:

        task_len = 0
        for ip in addr_list:
            if isinstance(ip, IPv4Network) or isinstance(ip, IPv6Network):
                task_len += sum(1 for _ in ip.hosts())
            elif isinstance(ip, IPv4Address) or isinstance(ip, IPv6Address):
                task_len += 1

        # The real logic
        for ns in nameserver:
            output_json_data = dict()
            resolver.nameservers = [ns]
            task_id = progress.add_task(f"Querying DNS server [blue bold]{ns}[/]", total=task_len,
                                        visible=not silent)
            for ip in addr_list:
                progress.update(task_id=task_id, advance=1)
                # Check if the address is a network or host
                if isinstance(ip, IPv4Network) or isinstance(ip, IPv6Network):
                    for i in ip.hosts():
                        # Loop for each address
                        name = dns.reversename.from_address(str(i))
                        try:
                            progress.update(task_id=task_id, advance=1)
                            resp = resolver.resolve(name, 'PTR', raise_on_no_answer=False).response
                            resp_list = sort_answers(resp)
                            output_json_data.update({str(i): resp_list})
                        except dns.resolver.NXDOMAIN:
                            output_json_data.update({str(i): "NXDOMAIN"})
                        except AttributeError:
                            pass
                        except dns.exception.Timeout:
                            console.print(f"DNS server didn't respond in time")
                            output_json_data.update({str(i): "Server Timeout"})
                            # console.print(f"Exiting.")
                            # break
                elif isinstance(ip, IPv4Address) or isinstance(ip, IPv6Address):
                    name = dns.reversename.from_address(str(ip))
                    try:
                        progress.update(task_id=task_id, advance=1)
                        resp = resolver.resolve(name, 'PTR', raise_on_no_answer=False).response
                        resp_list = sort_answers(resp)
                        output_json_data.update({str(i): resp_list})
                    except dns.resolver.NXDOMAIN:
                        output_json_data.update({str(i): "NXDOMAIN"})
                    except AttributeError:
                        pass
                    except dns.exception.Timeout:
                        console.print(f"DNS server didn't respond in time")
                        output_json_data.update({str(i): "Server Timeout"})
                        console.print(f"Exiting.")
                        sys.exit(1)

            output_json_dict.update({ns: output_json_data})

    if show_json:
        console.print_json(dumps(output_json_dict))
    else:
        # Generate the table for regular viewing
        for ns in output_json_dict:
            for addr in output_json_dict.get(ns):
                if verbose:
                    table.add_row(addr, str(output_json_dict.get(ns).get(addr)), ns)
                elif output_json_dict.get(ns).get(addr) != "NXDOMAIN":
                    table.add_row(addr, str(output_json_dict.get(ns).get(addr)), ns)

        console.print(table)

if __name__ == "__main__":
    main()
