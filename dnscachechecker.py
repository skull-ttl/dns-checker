import subprocess
import re
import requests
from collections import Counter

# ------------- Blocklist Fetchers --------------

def fetch_urlhaus_domains():
    print("[*] Fetching URLhaus...")
    try:
        resp = requests.get('https://urlhaus.abuse.ch/downloads/text/', timeout=30)
        resp.raise_for_status()
        return set(re.findall(r'://([a-zA-Z0-9\.\-]+)', resp.text))
    except Exception as e:
        print(f"[!] Failed to fetch URLhaus: {e}")
        return set()

def fetch_openphish_domains():
    print("[*] Fetching OpenPhish...")
    try:
        resp = requests.get('https://openphish.com/feed.txt', timeout=30)
        resp.raise_for_status()
        return set(re.findall(r'://([a-zA-Z0-9\.\-]+)', resp.text))
    except Exception as e:
        print(f"[!] Failed to fetch OpenPhish: {e}")
        return set()

def fetch_stevenblack_domains():
    print("[*] Fetching StevenBlack/hosts...")
    try:
        resp = requests.get('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', timeout=30)
        resp.raise_for_status()
        return set(re.findall(r"0\.0\.0\.0\s+([^\s#]+)", resp.text))
    except Exception as e:
        print(f"[!] Failed to fetch StevenBlack/hosts: {e}")
        return set()

def fetch_all_malicious_domains():
    domains = set()
    domains |= fetch_urlhaus_domains()
    domains |= fetch_openphish_domains()
    domains |= fetch_stevenblack_domains()
    print(f"[*] Total unique malicious domains loaded: {len(domains)}")
    return domains

# ------------- Known-Good Domains --------------

KNOWN_GOOD_DOMAINS = {
    "google.com", "www.google.com",
    "microsoft.com", "www.microsoft.com",
    "windowsupdate.com", "office.com",
    "bing.com", "outlook.com",
    "youtube.com", "cloudflare.com", "amazon.com", "aws.amazon.com",
    "apple.com", "facebook.com", "twitter.com", "github.com",
    "githubusercontent.com", "linkedin.com", "mozilla.org",
    "yahoo.com", "duckduckgo.com", "baidu.com", "reddit.com",
    "paypal.com", "instagram.com", "whatsapp.com", "telegram.org",
    "teams.microsoft.com", "skype.com", "live.com", "office365.com",
    "akamaitechnologies.com", "akadns.net",
    # Add more as needed for your environment
}

# ------------- PowerShell DNS Cache Parser --------------

def get_dns_cache_domains():
    print("[*] Getting local DNS cache (via PowerShell)...")
    try:
        cmd = ['powershell', '-Command', 'Get-DnsClientCache | Select-Object -ExpandProperty Entry']
        raw_output = subprocess.check_output(cmd)
        try:
            output = raw_output.decode('utf-8')
        except UnicodeDecodeError:
            output = raw_output.decode('cp850')
    except Exception as e:
        print(f"[!] Could not execute PowerShell Get-DnsClientCache: {e}")
        print("[!] Try running the script as Administrator if not already.")
        return []
    # Each domain is on its own line
    domains = [line.strip() for line in output.splitlines() if line.strip()]
    print(f"[*] Found {len(domains)} DNS cache entries.")
    return domains

# ------------- Main Categorization & Output --------------

def main():
    malicious_domains = fetch_all_malicious_domains()
    cache_domains = get_dns_cache_domains()
    freq = Counter(cache_domains)

    print("\n[*] Top 20 most frequent DNS cache domains (categorized):")
    print("     [RED] = Malicious  [GREEN] = Known-Good  [YELLOW] = Unsure/Manual Check\n")
    category_counts = {"malicious": 0, "good": 0, "unsure": 0}
    for domain, count in freq.most_common(20):
        if domain in malicious_domains:
            color, label = "\033[91m", "[MALICIOUS]"
            category_counts["malicious"] += 1
        elif domain in KNOWN_GOOD_DOMAINS or any(domain.endswith('.' + good) for good in KNOWN_GOOD_DOMAINS):
            color, label = "\033[92m", "[KNOWN-GOOD]"
            category_counts["good"] += 1
        else:
            color, label = "\033[93m", "[UNSURE]"
            category_counts["unsure"] += 1
        reset = "\033[0m"
        print(f"{color}{domain:45} {count:3d} {label}{reset}")

    print(f"\nSummary: {category_counts['malicious']} malicious, {category_counts['good']} known-good, {category_counts['unsure']} unsure/manual check")

    bad_hits = set(d for d in cache_domains if d in malicious_domains)
    if bad_hits:
        print("\n[!!!] Malicious domains found in your DNS cache:")
        for bd in sorted(bad_hits):
            print(f"   {bd}")
    else:
        print("\n[OK] No known malicious domains found in your DNS cache.")

    print("\n[INFO] Sources used for blocklists:")
    print(" - https://urlhaus.abuse.ch/downloads/text/")
    print(" - https://openphish.com/feed.txt")
    print(" - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
    print("\n[LEGAL] All lists used for research and personal security purposes. Read provider TOS before commercial/automated use.")

    print("=" * 40)
    print()
    print("For legal, educational, and ethical use only. The Trave Tricksters Legion and script contributors take no responsibility for misuse.")
    print()
    print("installation finished")
    print()

    ascii_art = r"""
        %%%%                                            *@%%%%@-                                %%%%
       %%%%%                                        %%%%%%%%%%%%%%%%%-                         @%%%%
      *%%*%%%                                     %%%%%%%%%%%%%%%%%%%%%%%                      %%%%%
      %%%:%%%                                   %%%%%%%%::::   ::::: %%%%%%%                  %%%: %
     %%% :-%%%                                %%%%%%%%  ::::::::::::: ::%%%%%%%               %%%- %
    %%%%::-*%%@                             %%%%%%%%*::::::::::::::::: ::  %%%%%%            %%%:-::
    %%%: :-:%%%                            %%%%%%%% :::::: ::::: ::::::: :: :%%%%%          -%%%- ::
   %%% :  :--%%@                          %%%%%%%%  ::::::::::::*-*-- ::::::::-%%%%%        %%%:-::
  %%%%: :: --%%%                         %%%%%%%%*:::::::::::::----------: :::: %%%%%      %%%*-::::
  %%%: ::::---%%%                       %%%%%%%%%::  :::::::  -----**----*-::::::*@%%%     %%%--::::
 %%% :::::::--*%%%%%%%%%%%%%%%%%%%-    *%%%%%%%% : :: :: ::::-----%-----------:::::%%%%   %%%*--::::
%%%: :::::: :%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%:::: :::  : -----%%%%%%%%%%%---*::: *%%%  %%%-- ::::
%%%::::::  %%%%%%%%:: ::   :-%%%%%%%%%%%%%%%%%%: :::::::::: ----%%%%%%%%%%%%%%*--*:: %%%%%%%---::: :
%%::::: :*%%%%%%:::: :::::::: :::: %%%%%%%%%%%%::   :::::: ----%%%%%%%%%%%%%%%%%%-- : %%%%%*--::::::
%:::::::%%%%%*:::::::: ::::: ::::::::%%%%%%%%%*:::::: ::: ----%%%%%%%%%%%%%%%%%%%%*-*:*%%%%---::: ::
%::: : %%%%%: ::: :::::  : ::: : :::::%%%%%%%% : ::::::::----%%%%%%%%%%%%%%%%%%%%%%%--:%%%%---:: :::
::::: %%%%%:  :: -----* ::  :: ::::::::%%%%%%% :::  ::::----%%%%%%%%%%%%%%*    *%%%%%%- %%%%-::: : :
: :: %%%%*:::: -----*----*: :::::::::: :%%%%%%::::: :::----%%%%%%%%%%%%%%*        %%%%%*-%%%-  :::::
::::%%%%%:  :------*%%%----*:: ::: ::::::%%%%*:::: : ----*%%%%%%%%%%%%%%%%:         %%%%%%%%% : : :
:  %%%%%::::-------%%%%%%----- :::::::::::*%%::::::*---*%%%%%%%%%%%%%%%%%%%%        %%%%%%%%%%%% :::
:: %%%% :::-----%%%%%%%%%%%----::::: :: ::::% :::::::: :: %%%%%%%%%%%%%%%%%%*      *%%%%%    %*%% :
::*%%%%:: ----%%%%%%%%%%%%%%*----::::::::::::: ::: ::: %%%%%%%%%%%%%%%%%%%%%%      %%%%%     *%%%%
::%%%% ::---*%%%%%%%%%%%%%%%%%%----:::  :: :  ::::::%%%%%%%%%%%%%%%%%%%%%%%%%%    %%%%%%    :%@%%%::
: %%%%::---%%%%%%%%%%%%%%%%%%--%%%%%%%%- ::::::: -%%%%%%%%%%%%%%%%%%%%%%%%%%%%   %%%%%%%%-   %%%% ::
  %%%%::--%%%%%%%%%%%%%%%%%%-%%%%%%%%%%%%%-::: %%%%%%%@          %%%%%%%%%%%%%   %%%%-*%%%%%%%%%::::
::%%%%:--%%%%%%*: :::::%%%%%%%%:      %%%%%%%%%%%%*                 %%%%%%%%%%  %%%%-----***-:::::::
  %%%% -%%%%%%:  :: :::-%%%%%*           @%%%%%%*                    %%%%*%%%% %%%%-------: ::: : ::
::%%%%:%%%%% :: ::::: : %%%%@               %%            %%%%%%      %%%%%%%%%%%%-------::::::  :%%
::*%%%%%%%%:: ::::: :: :%%%%  %%%                       %%%%%%**%-    %%%%%%%%%%%-------- ::::::::*%
:: %%%%%%*::: ::::::::::%%%%%%%%%%%                   %%%%%%          %%%%%%%%%%--------:::::: :  %%
::%%%%%%%%%::::  ::: ::: %%%% -%%%%%*               @%%%%%-%%*        %%%%%%%%%--------::::::: :  ::
:%%%%   *%%%% :::::: ::::*%%%: @%%%%%%%       %   @%%%%%   %%%        %%%%%%%%%-------::::: :: : :::
%%%-      %%% ::::::::::::%%%%  %  %%%%%*%:   %%%%%%%%    %%%%        @%%%%%%%%------ ::::::: ::::::
%%%*    : %%%%%**:  ::::::%%%%% %%   %%%%%    -%%%%%    %%%%%         %%%%%%%%%-----  :::  ::-**%%%%
%%%%% :  %%%%%%%%%%%%%%%%%%%%%   %%%%@%%%*     %%%%%%%%%%%%           %%%%%%%%-*%%%%%%%*%%%%%%%%%%%%
  %%%%%%%%%%: ::  :*%%%%%%%%%:     @*%%%%:     @                      %%%%%%%%%%%%%%%%%%%%%-   :::::
::: -%%%* :::::::::::----%%%%          @%                             %%%%%%%%%---------::::  ::::::
 :::%%% :::: :::: :: ----%%%%%         %%       %@%*                 *%%%%%%%%%-----:%%:: :::  :::::
:::%%%%%:::::::::: : -----%%%%        %            %%  @%%%%%%%      %%%%%%%%%%-----%%%%::: : : :::
 : %%%%%:::: ::::    -----*%%%%   %  %%           %%-     %%% :     -%%%%%%%%%%-----%%%%::: :  :-:::
: :%%%%% :::: :::%%%:------%%%%%  *%  %%      %%%%      %%%%        %%%%%%%%%%%----:%%%%-:::: ::::
:  %%%%% ::::: ::%%%:------%%%%%%@ - %*%%*@@%%%     @%%@ %%        %%%%%%%%%%%%-----%%%%-:::: :  :::
:::::::::::::::::  ::------%%%%%%%%   %%%%%%%%%%%%%%*   %%        %%%%%%%%%%%%%---------:::  :::::::
: ::::: ::::: :: ::: ------%%%%%%%%%   %%             @:%%       %%%%%%%%%%%%%*---------::::::::::::
:::: ::::::::::::: ::------%%%%%%%%%%  @%%             %%      %%%%%%%%%%%%%%%%%%%*-:---: ::::::::::
::  ::: ::: : :::::::------%%%%%%%%%%%  *%           *%%      %%%%%%%%%%%%-*%%%%%%%%%%%%%%%%%%%%%%%-
%%%%%%%%%%%%%%%%%%%%***---*%%%%%%%%%%%@  %%        @%%%      %%%%%%%%%%%%%%%:--:*%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   %%%%%%%%%%%       %%%%%%%%%%%%%%%%%%---:-----::-%%%%%%%%%%
: : : ::::  :::::%%%%%%%%%%% :::%%%%%%%*                  %%%%%%%%%%%%%%%%%%%%%%*-----:-%%%%*%% : ::
%%%%%%%%%%%%%%%%%%%%%%%:::::::%%%%%%%%%%*       *%       %%%%%%%%%%%*-::--****-::--:-%%%%%%%%%%%%%%%
::::: :::    %%*%%%%  :::::  ::  :  %%%%%               %%%%%%%%%%%%%------------------:-%%%%%%%%%%%
:: : ::::: %%%%%%%%%%%%%%%%%::::::::*%%%%%            :%%%%%%%%%%%%%%%--:-----:------:------:*%%%%%%
:: : :: :-%%%%%%%- %%%%%%*%%%:: :: ::%%*%%%          %%%%%%%%%%%%%%%%%----:-:----:----:-*%%%%%%%%%%%
::::: ::%%%%%%:::%%%%%%%%%%%%:::::: %%%%%%%%%%%%%%%%%%%%%%%%%%*%%%%%%%%:-:-:%%%%%%%%%%%%%%%%%%%%%%%%
::%%%: %%%%%:   %%%%%%%%%%%%% : :::%%%%%%%%%%%%%%%%%%%%%%%%%%-----*%%%%%----%%%%%%*%%%%%%%%%%%%%:---
 :%%%%%%%%%::::%%%%%%%%%%%%%*:::::%%%%%%%%%:%%%%%%%%%%%%%%%%-----::--:*%%---*%%%%%%%%%%%%%%%:---:---
::%%%%%%%% ::-%%%%%%%%%%%%%% ::::%%%%%% :: ::%%%%*%%%%%%%%%-----:-----------:%%%%%%%%%%%:-----:---::
::%%%%%%*:::-%%%%%%%%%%%%%%%:: :%*:::: :::::::%%%%%%%%%%%*----:%%%%--------:-%%%%%%%------------: ::
: %%%%%*:::-%%%%%%%%%%%%%%%%  ::::::::*%%% ::::%%%%%%%%%----:*%%%%%%%%%%*:---:%%%%---:--:---:% :::::
 %%%%%::: :%%%%%%%%%%%%%%%% :::: :%%%%%%%%%*::::*%%%%%%-----%%%%%%%%%%%%%%%%%%%%%%--------:%%:::::::
%%%%%-::: %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% ::: %%%*:----%%%%%%%%%%%%%%%%%%%%%%%%:--:--%%% :::::::
%%%%%: : %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*%%%%%%%::::% ::--%%%%%%%%%%%%%%%%%%%--**%**-----%%% ::::::::

Happy hacking!
— The Trave Tricksters Legion CTF Team
"""
    print(ascii_art)

if __name__ == "__main__":
    main()
