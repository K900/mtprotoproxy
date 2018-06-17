TIMEOUT = 5


def init_ip_info():
    try:
        with urllib.request.urlopen('https://v4.ifconfig.co/ip', timeout=TIMEOUT) as f:
            if f.status != 200:
                raise Exception("Invalid status code")
            my_ip_info["ipv4"] = f.read().decode().strip()
    except Exception:
        pass

    if PREFER_IPV6:
        try:
            with urllib.request.urlopen('https://v6.ifconfig.co/ip', timeout=TIMEOUT) as f:
                if f.status != 200:
                    raise Exception("Invalid status code")
                my_ip_info["ipv6"] = f.read().decode().strip()
        except Exception:
            PREFER_IPV6 = False
        else:
            print_err("IPv6 found, using it for external communication")

    if USE_MIDDLE_PROXY:
        if ((not PREFER_IPV6 and not my_ip_info["ipv4"]) or
                (PREFER_IPV6 and not my_ip_info["ipv6"])):
            print_err("Failed to determine your ip, advertising disabled")
            USE_MIDDLE_PROXY = False
