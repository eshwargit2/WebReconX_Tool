import nmap

def fast_scan(target):
    nm = nmap.PortScanner()

    print(f"\nâš¡ Fast scanning: {target}\n")

    # FAST scan arguments
    args = "-sS -T4 --top-ports 50 --open -sV --version-light"

    nm.scan(hosts=target, arguments=args)

    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}\n")

        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto.upper()}")

            for port in sorted(nm[host][proto].keys()):
                s = nm[host][proto][port]
                print(
                    f"  Port: {port:<5} | "
                    f"Service: {s['name']:<10} | "
                    f"Version: {s.get('product','')} {s.get('version','')}"
                )
        print("-" * 50)


if __name__ == "__main__":
    target = input("Enter Website / IP: ")
    fast_scan(target)
