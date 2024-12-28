import requests
import sys
from colorama import Fore, Style, init

# Ініціалізація colorama
init(autoreset=True)

def print_art():
    art = r"""
     __      __             _       _             
     \ \    / /__ _ _ _ ___| |_ ___| |__  ___ _ _ __
      \ \/\/ / _ \ '_| / -_)  _/ -_) '_ \/ -_) '_/ _ \
       \_/\_/  __/_| |_\___|\__\___|_.__/\___|_| \___/
                                                  
    """
    print(Fore.CYAN + art)

def check_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers

        # Заголовки, які ми хочемо перевірити
        checks = {
            "Host": headers.get("Host"),
            "X-Forwarded-Host": headers.get("X-Forwarded-Host"),
            "Origin": headers.get("Origin"),
            "Referer": headers.get("Referer"),
            "X-Forwarded-For": headers.get("X-Forwarded-For"),
            "Access-Control-Allow-Origin": headers.get("Access-Control-Allow-Origin"),
            "Access-Control-Allow-Credentials": headers.get("Access-Control-Allow-Credentials"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
            "X-Cache": headers.get("X-Cache"),
            "Set-Cookie": headers.get("Set-Cookie"),
        }

        vulnerabilities = []

        # Перевірка на CORS
        if checks["Access-Control-Allow-Origin"] is None or checks["Access-Control-Allow-Origin"] == "*":
            vulnerabilities.append("CORS vulnerability may exist.")

        # Перевірка на CSRF
        if checks["X-Frame-Options"] is None:
            vulnerabilities.append("Potential CSRF vulnerability (X-Frame-Options not set).")

        # Перевірка на Clickjacking
        if checks["X-Frame-Options"] is None or "DENY" not in checks["X-Frame-Options"]:
            vulnerabilities.append("Potential Clickjacking vulnerability (X-Frame-Options not set or too permissive).")

        # Перевірка на Web Cache Poisoning
        if checks["X-Cache"] is not None and "HIT" in checks["X-Cache"]:
            vulnerabilities.append("Potential Web Cache Poisoning (X-Cache HIT).")

        # Перевірка на SameSite
        if checks["Set-Cookie"] and "SameSite=None" in checks["Set-Cookie"] and "Secure" not in checks["Set-Cookie"]:
            vulnerabilities.append("SameSite attribute may lead to CSRF if not set securely.")

        return checks, vulnerabilities

    except Exception as e:
        print(Fore.RED + f"An error occurred while checking {url}: {e}")
        return None, []

def extract_session_cookies(cookies):
    """Extract session cookies."""
    session_cookies = {name: value for name, value in cookies.items() if 'session' in name.lower()}
    return session_cookies

def save_to_file(url, checks, vulnerabilities, output_file):
    with open(output_file, 'a') as f:
        f.write(f"Checked URL: {url}\n")
        for header, value in checks.items():
            f.write(f"{header}: {value}\n")
        if vulnerabilities:
            f.write("Vulnerabilities detected:\n")
            for v in vulnerabilities:
                f.write(f"- {v}\n")
        f.write("\n")

def main():
    print_art()
    
    mode = None
    urls = []
    output_file = None

    # Читання аргументів командного рядка
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "-h":
            print(Fore.YELLOW + "Usage: python script.py [options] [urls...]")
            print("Options:")
            print("  -full       Show all headers and vulnerabilities")
            print("  -voln       Show only detected vulnerabilities")
            print("  -headers    Show all headers excluding cookies")
            print("  -cookie     Show only session cookies")
            print("  -f <file>   Read URLs from a file")
            print("  -o <file>   Save output to a text file")
            return
        elif arg in ["-voln", "-full", "-headers", "-cookie"]:
            mode = arg
        elif arg == "-o":
            i += 1
            if i < len(sys.argv):
                output_file = sys.argv[i]
            else:
                print(Fore.RED + "Output filename cannot be empty.")
                return
        elif arg == "-f":
            i += 1
            if i < len(sys.argv):
                filename = sys.argv[i]
                try:
                    with open(filename, "r") as file:
                        urls.extend([line.strip() for line in file if line.strip()])
                except Exception as e:
                    print(Fore.RED + f"Error reading file: {e}")
                    return
            else:
                print(Fore.RED + "Filename cannot be empty.")
                return
        else:
            urls.append(arg)  # Додаємо URL напряму
        i += 1

    # Перевірка, чи є URL
    if not urls:
        print(Fore.RED + "No URLs provided.")
        return

    for url in urls:
        url = url.strip()  # Обрізаємо пробіли
        checks, vulnerabilities = check_headers(url)

        if checks:
            if mode == "-voln":
                if vulnerabilities:
                    output_str = f"\nVulnerabilities detected for {url}:\n"
                    for v in vulnerabilities:
                        output_str += f"{Fore.RED}- {v}\n"
                else:
                    output_str = f"No vulnerabilities detected for {url}.\n"

            elif mode == "-headers":
                output_str = f"\nChecked URL: {url}\n"
                for header, value in checks.items():
                    if header != "Set-Cookie":  # Вигадуємо куки
                        output_str += f"{Fore.MAGENTA}{header}: {Fore.BLUE}{value}\n"

            elif mode == "-cookie":
                session_cookies = extract_session_cookies(requests.get(url).cookies)
                output_str = Fore.GREEN + f"\nSession cookies for {url}:\n"
                for name, value in session_cookies.items():
                    output_str += f"{Fore.MAGENTA}{name}: {Fore.BLUE}{value}\n"

            elif mode == "-full" or mode is None:
                output_str = f"\nChecked URL: {url}\n"
                for header, value in checks.items():
                    output_str += f"{Fore.MAGENTA}{header}: {Fore.BLUE}{value}\n"

                if vulnerabilities:
                    output_str += Fore.RED + f"\nVulnerabilities detected for {url}:\n"
                    for v in vulnerabilities:
                        output_str += Fore.RED + f"- {v}\n"

            print(output_str)

            # Зберегти вихідні дані у файл, якщо зазначено
            if output_file:
                save_to_file(url, checks, vulnerabilities, output_file)

    print(Fore.CYAN + "Check completed.")

if __name__ == "__main__":
    main()

