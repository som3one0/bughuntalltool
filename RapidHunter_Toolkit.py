import os

def main():
    create_directories()
    clear_screen()

    print("[ALL IN ONE TOOL INSTALLER] Checking and installing missing tools ...")

    while True:
        print("\nMenu:")
        print("1- Check installed tools")
        print("2- Install all tools")
        print("3- Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            check_tools()
        elif choice == '2':
            install_all_tools()
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please choose a valid option.")

def create_directories():
    directories = [
        '/root/Tools/ALLInOne/tools/file',
        '/root/Tools/ALLInOne/tools/go/bin',
        '/root/Tools/wordlist',
        '/root/Tools/templates'
    ]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def clear_screen():
    os.system('clear')

def check_tool_installed(tool_name):
    return os.system(f"command -v {tool_name} > /dev/null 2>&1") == 0 

def install_tool(tool_name, install_command):
    if not check_tool_installed(tool_name):
        print(f"[INSTALLING] {tool_name} ...")
        status = os.system(install_command)
        if status == 0:
            print(f"[INSTALLING] {tool_name} is installed!")
        else:
            print(f"[INSTALLING] {tool_name} installation failed.")
    else:
        print(f"[EXISTING] {tool_name} is already installed.")

def check_tools():
    required_tools = [
        "python", "python2", "python3", "pip", "unzip", "curl", "snap", "jq",
        "python-pip", "snapd", "python3-pip", "go", "git", "shodan", "massdns",
        "chaos", "gotator", "nuclei", "httpx", "gospider", "hakrawler", "subjs",
        "getJS", "gau", "ffuf", "gobuster", "wfuzz", "dirsearch", "masscan",
        "naabu", "mapcidr", "wpscan", "linkfinder", "secretfinder", "anti-burl",
        "unfurl", "anew", "gron", "qsreplace", "interlace", "jq", "cf-check",
        "tmux", "uro", "certcrunchy", "analyticsrelationships", "galer", "altdns",
        "aquatone", "gowitness", "httprobe", "paramspider", "waybackurls",
        "gauplus", "nuclei", "jsscanner", "gitgraber", "githacker", "gittools",
        "dumpsterdiver", "earlybird", "ripgrep", "gau-expose","CertCrunchy", "chaos-client", "gotator", "AnalyticsRelationships",
        "galer", "massdns", "mapcidr", "katana", "naabu", "httpx",
        "gowitness", "httprobe", "Gospider", "hakrawler", "ParamSpider",
        "waybackurls", "gauplus", "mapcidr", "ffuf", "gobuster",
        "wfuzz", "dirsearch", "masscan", "nuclei", "gitGraber",
        "SecretFinder", "subjs", "getJS", "JSScanner", "GitHacker",
        "gitGraber", "gitDorker", "nuclei-templates", "fuzzing-templates",
        "DumpsterDiver", "earlybird", "ripgrep", "Gau-Expose", "installallurls",
        "anti-burl", "unfurl", "anew", "gron", "qsreplace", "Interlace",
        "cf-check", "tmux", "uro"
    ]

    print("Checking installation status of required tools...")

    for tool in required_tools:
        if check_tool_installed(tool) or os.system(f"find / -type f -name {tool} 2>/dev/null") == 0:
            print(f"[INSTALLED] {tool}")
        else:
                print(f"[MISSING] {tool}")

def install_all_tools():
    print("[INSTALLING ALL TOOLS] Installing all tools ...")

    install_packages()
    subdomains_enumeration()
    dns_resolver()
    visual_tools()
    http_probe()
    web_crawling()
    network_scanner()
    http_parameter()
    fuzzing_tools()
    wordlists()
    cms_scanner()
    vulns_scanner()
    js_hunting()
    git_hunting()
    sensitive_finding()
    useful_tools()

    print("[TOOLS INSTALLED] All tools have been installed.")

def install_packages():
    print("[ENVIRONMENT] Installing required packages ...")
    required_packages = [
        ("python", "apt-get install python -y"),
        ("python2", "apt-get install python2 -y"),
        ("python3", "apt-get install python3 -y"),
        ("pip", "apt-get install pip -y"),
        ("unzip", "apt-get install unzip -y"),
        ("curl", "apt install curl -y"),
        ("snap", "apt install snap -y"),
        ("jq", "apt install jq -y"),
        ("python-pip", "apt install python-pip -y"),
        ("snapd", "apt install snapd -y"),
        ("python3-pip", "apt install python3-pip -y")
    ]

    for package, install_command in required_packages:
        install_tool(package, install_command)

    print("[ENVIRONMENT] Required packages are installed!")

def subdomains_enumeration():
    print("[SUBDOMAINS ENUMERATION] Golang installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools/file && wget https://go.dev/dl/go1.20.5.linux-amd64.tar.gz && tar -zxvf go1.20.5.linux-amd64.tar.gz -C /usr/local/')
    print("[SUBDOMAINS ENUMERATION] CertCrunchy installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools/file && git clone https://github.com/joda32/CertCrunchy.git > /dev/null 2>&1')
    os.system('cd CertCrunchy && sudo pip3 install -r requirements.txt')
    print("[SUBDOMAINS ENUMERATION] CertCrunchy installation is done !")

    print("[SUBDOMAINS ENUMERATION] chaos installation in progress ...")
    os.system('go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/chaos /usr/local/bin/')
    print("[SUBDOMAINS ENUMERATION] chaos installation is done !")

    print("[SUBDOMAINS ENUMERATION] shodan installation in progress ...")
    os.system('shodan init Dw9DTE811cfQ6j59jGLfVAWAMDr0MCTT && apt install python3-shodan')
    print("[SUBDOMAINS ENUMERATION] shodan installation is done !")

    print("[SUBDOMAINS ENUMERATION] gotator installation in progress ...")
    os.system('go install github.com/Josue87/gotator@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/gotator /usr/local/bin/')
    print("[SUBDOMAINS ENUMERATION] gotator installation is done !")

    print("[SUBDOMAINS ENUMERATION] AnalyticsRelationships installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/Josue87/AnalyticsRelationships.git  > /dev/null 2>&1')
    os.system('cd AnalyticsRelationships && go build -ldflags "-s -w"')
    print("[SUBDOMAINS ENUMERATION] AnalyticsRelationships installation is done !")

    print("[SUBDOMAINS ENUMERATION] Galer installation in progress ...")
    os.system('GO111MODULE=on go install -v github.com/dwisiswant0/galer@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/galer /usr/local/bin/')
    print("[SUBDOMAINS ENUMERATION] Galer installation is done !")


def dns_resolver():
    print("[DNS RESOLVER] MassDNS installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/blechschmidt/massdns.git')
    os.system('cd massdns && make && make install')
    print("[DNS RESOLVER] Mapcidr installation in progress ...")
    os.system('go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/mapcidr /usr/local/bin/')
    print("[DNS RESOLVER] Mapcidr installation is done !")

    print("[DNS RESOLVER] AltDns installation in progress ...")
    os.system('pip3 install py-altdns==1.0.2 && pip install py-altdns')
    print("[DNS RESOLVER] AltDns installation is done !")

def visual_tools():
    print("[VISUAL /root/Tools/ALLInOne/tools] Aquatone installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools/file && wget install https://github.com/michenriksen/aquatone/releases/download/v$AQUATONEVER/aquatone_linux_amd64_$AQUATONEVER.zip')
    os.system('unzip aquatone_linux_amd64_$AQUATONEVER.zip')
    os.system('mv aquatone /usr/local/bin/')
    print("[VISUAL /root/Tools/ALLInOne/tools] Aquatone installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools/file && wget install https://github.com/michenriksen/aquatone/releases/download/v$AQUATONEVER/aquatone_linux_amd64_$AQUATONEVER.zip > /dev/null 2>&1')
    os.system('unzip aquatone_linux_amd64_$AQUATONEVER.zip > /dev/null 2>&1')
    os.system('mv aquatone /usr/local/bin/')
    print("[VISUAL /root/Tools/ALLInOne/tools] Aquatone installation is done !")

    print("[VISUAL /root/Tools/ALLInOne/tools] Gowitness installation in progress ...")
    os.system('go install github.com/sensepost/gowitness@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/gowitness chmod +x /usr/local/bin/')
    print("[VISUAL /root/Tools/ALLInOne/tools] Gowitness installation is done !")

def http_probe():
    print("[HTTP PROBE] httpx installation in progress ...")
    os.system('GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest')
    os.system('ln -s ~/go/bin/httpx /usr/local/bin/')
    print("[HTTP PROBE] httprobe installation in progress ...")
    os.system('go install github.com/tomnomnom/httprobe@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/httprobe /usr/local/bin/')
    print("[HTTP PROBE] httprobe installation is done !")

def web_crawling():
    print("[WEB CRAWLING] Gospider installation in progress ...")
    os.system('go install github.com/jaeles-project/gospider@latest')
    os.system('ln -s ~/go/bin/gospider /usr/local/bin/')
    print("[WEB CRAWLING] Gospider installation in progress ...")
    os.system('go install github.com/jaeles-project/gospider@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/gospider /usr/local/bin/')
    print("[WEB CRAWLING] Gospider installation is done !")

    print("[WEB CRAWLING] Hakrawler installation in progress ...")
    os.system('go install github.com/hakluke/hakrawler@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/hakrawler /usr/local/bin/')
    print("[WEB CRAWLING] Hakrawler installation is done !")

    print("[WEB CRAWLING] ParamSpider installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/devanshbatham/ParamSpider > /dev/null 2>&1')
    os.system('cd ParamSpider && pip3 install -r requirements.txt')
    print("[WEB CRAWLING] ParamSpider installation is done !")

    print("[WEB CRAWLING] Waybackurls installation in progress ...")
    os.system('go install github.com/tomnomnom/waybackurls@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/waybackurls /usr/local/bin/')
    print("[WEB CRAWLING] Waybackurls installation is done !")

    print("[WEB CRAWLING] Gauplus installation in progress ...")
    os.system('GO111MODULE=on go install -v github.com/dwisiswant0/gauplus@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/gauplus /usr/local/bin/')
    print("[WEB CRAWLING] Gauplus installation is done !")

    print("[WEB CRAWLING] katana installation in progress ...")
    os.system('go install github.com/projectdiscovery/katana/cmd/katana@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/katana /usr/local/bin/')
    print("[WEB CRAWLING] katana installation is done !")

def network_scanner():
    print("[NETWORK SCANNER] Masscan installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/robertdavidgraham/masscan > /dev/null 2>&1')
    os.system('cd masscan && make > /dev/null 2>&1 && make install > /dev/null 2>&1 && mv bin/masscan /usr/local/bin/')
    print("[NETWORK SCANNER] Masscan installation is done !")

    print("[NETWORK SCANNER] Naabu installation in progress ...")
    os.system('GO111MODULE=on go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest > /dev/null 2>&1')
    os.system('ln -s ~/go/bin/naabu /usr/local/bin/')
    print("[NETWORK SCANNER] Naabu installation is done !")

def http_parameter():
    print("[HTTP PARAMETER DISCOVERY] Arjun installation in progress ...")
    os.system('pip3 install arjun > /dev/null 2>&1')
    os.system('cd /root/Tools/ALLInOne/tools/file && git clone https://github.com/edduu/Arjun.git')
    print("[HTTP PARAMETER DISCOVERY] Arjun installation is done !")

    print("[HTTP PARAMETER DISCOVERY] x8 installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools/file && install https://github.com/Sh1Yo/x8/releases/download/v"$X8VER"/x8_linux.tar.gz > /dev/null 2>&1')
    os.system('tar -zxvf x8_linux.tar.gz > /dev/null 2>&1')
    os.system('mv x8 /usr/local/bin/x8')
    print("[HTTP PARAMETER DISCOVERY] x8 installation is done !")

def fuzzing_tools():
    print("[FUZZING TOOLS] ffuf installation in progress ...")
    os.system('go install github.com/ffuf/ffuf@latest > /dev/null 2>&1 && ln -s ~/go/bin/ffuf /usr/local/bin/')
    print("[FUZZING TOOLS] ffuf installation is done !")

    print("[FUZZING TOOLS] Gobuster installation in progress ...")
    os.system('go install github.com/OJ/gobuster/v3@latest > /dev/null 2>&1 && ln -s ~/go/bin/gobuster /usr/local/bin/')
    print("[FUZZING TOOLS] Gobuster installation is done !")

    print("[FUZZING TOOLS] wfuzz installation in progress ...")
    os.system('apt-install install wfuzz -y > /dev/null 2>&1')
    print("[FUZZING TOOLS] wfuzz installation is done !")

    print("[FUZZING TOOLS] dirsearch installation in progress ...")
    os.system('sudo pip3 install git+https://github.com/maurosoria/dirsearch &>/dev/null')
    print("[FUZZING TOOLS] dirsearch installation is done !")


def wordlists():
    print("[WORDLISTS] SecLists installation in progress ...")
    os.system('cd /root/Tools/wordlist && git clone https://github.com/danielmiessler/SecLists.git > /dev/null 2>&1')
    os.system('cd /root/Tools/wordlist && git clone https://github.com/orwagodfather/WordList.git  > /dev/null 2>&1')
    os.system('cd /root/Tools/wordlist && git clone https://github.com/mrco24/mrco24-wordlist.git > /dev/null 2>&1')
    print("[WORDLISTS] SecLists installation is done !")

def cms_scanner():
    print("[CMS SCANNER] WPScan installation in progress ...")
    os.system('gem install wpscan > /dev/null 2>&1')
    print("[CMS SCANNER] WPScan installation is done !")

def vulns_scanner():
    print("[VULNERABILITY SCANNER] Nuclei installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && wget https://github.com/projectdiscovery/nuclei/releases/download/v2.9.7/nuclei_2.9.7_linux_amd64.zip && unzip nuclei_2.9.7_linux_amd64.zip > /dev/null 2>&1 && ln -s ~/go/bin/nuclei /usr/local/bin/')
    os.system('cd /root/Tools/templates && git clone https://github.com/projectdiscovery/nuclei-templates.git > /dev/null 2>&1')
    os.system('cd /root/Tools/templates && git clone https://github.com/projectdiscovery/fuzzing-templates.git > /dev/null 2>&1')
    print("[VULNERABILITY SCANNER] Nuclei installation is done !")

def js_hunting():
    print("[JS FILES HUNTING] Linkfinder installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/GerbenJavado/LinkFinder.git > /dev/null 2>&1 && cd LinkFinder && pip3 install -r requirements.txt > /dev/null 2>&1 && python3 setup.py install > /dev/null 2>&1')
    print("[JS FILES HUNTING] Linkfinder installation is done !")

    print("[JS FILES HUNTING] SecretFinder installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/m4ll0k/SecretFinder.git > /dev/null 2>&1 && cd SecretFinder && pip3 install -r requirements.txt && pip3 install jsbeautifier && pip3 install lxml > /dev/null 2>&1')
    print("[JS FILES HUNTING] SecretFinder installation is done !")

    print("[JS FILES HUNTING] subjs installation in progress ...")
    os.system('go install -u github.com/lc/subjs@latest > /dev/null 2>&1 && ln -s ~/go/bin/subjs /usr/local/bin/')
    print("[JS FILES HUNTING] subjs installation is done !")

    print("[JS FILES HUNTING] Getjs installation in progress ...")
    os.system('go install github.com/003random/getJS@latest > /dev/null 2>&1 && ln -s ~/go/bin/getJS /usr/local/bin/')
    print("[JS FILES HUNTING] Getjs installation is done !")

    print("[JS FILES HUNTING] Jsscanner installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/dark-warlord14/JSScanner > /dev/null 2>&1 && cd JSScanner/ && bash install.sh > /dev/null 2>&1')
    print("[JS FILES HUNTING] Jsscanner installation is done !")

def git_hunting():
    print("[GIT HUNTING] gitGraber installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/obheda12/GitDorker.git > /dev/null 2>&1 && cd GitDorker && pip3 install -r requirements.txt > /dev/null 2>&1')
    print("[GIT HUNTING] gitGraber installation is done !")

    print("[GIT HUNTING] gitGraber installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/hisxo/gitGraber.git > /dev/null 2>&1 && cd gitGraber && pip3 install -r requirements.txt > /dev/null 2>&1')
    print("[GIT HUNTING] gitGraber installation is done !")

    print("[GIT HUNTING] GitHacker installation in progress ...")
    os.system('pip3 install GitHacker > /dev/null 2>&1')
    print("[GIT HUNTING] GitHacker installation is done !")

    print("[GIT HUNTING] GitTools installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/internetwache/GitTools.git > /dev/null 2>&1')
    print("[GIT HUNTING] GitTools installation is done !")

def sensitive_finding():
    print("[SENSITIVE FINDING TOOLS] DumpsterDiver installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/securing/DumpsterDiver.git > /dev/null 2>&1 && cd DumpsterDiver && pip3 install -r requirements.txt > /dev/null 2>&1')
    print("[SENSITIVE FINDING TOOLS] DumpsterDiver installation is done !")

    print("[SENSITIVE FINDING TOOLS] EarlyBird installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/americanexpress/earlybird.git > /dev/null 2>&1 && cd earlybird && ./build.sh > /dev/null 2>&1 && ./install.sh > /dev/null 2>&1')
    print("[SENSITIVE FINDING TOOLS] EarlyBird installation is done !")

    print("[SENSITIVE FINDING TOOLS] Ripgrep installation in progress ...")
    os.system('apt-install install -y ripgrep > /dev/null 2>&1')
    print("[SENSITIVE FINDING TOOLS] Ripgrep installation is done !")

    print("[SENSITIVE FINDING TOOLS] Gau-Expose installation in progress ...")
    os.system('cd /root/Tools/ALLInOne/tools && git clone https://github.com/tamimhasan404/Gau-Expose.git > /dev/null 2>&1')
    print("[SENSITIVE FINDING TOOLS] Gau-Expose installation is done !")

def useful_tools():
    print("[USEFUL TOOLS] installallurls installation in progress ...")
    os.system('GO111MODULE=on go install -v github.com/lc/gau@latest > /dev/null 2>&1 && ln -s ~/go/bin/gau /usr/local/bin/')
    print("[USEFUL TOOLS] installallurls installation is done !")

    print("[USEFUL TOOLS] anti-burl installation in progress ...")
    os.system('go install github.com/tomnomnom/hacks/anti-burl@latest > /dev/null 2>&1 && ln -s ~/go/bin/anti-burl /usr/local/bin/')
    print("[USEFUL TOOLS] anti-burl installation is done !")

    print("[USEFUL TOOLS] unfurl installation in progress ...")
    os.system('go install github.com/tomnomnom/unfurl@latest > /dev/null 2>&1 && ln -s ~/go/bin/unfurl /usr/local/bin/')
    print("[USEFUL TOOLS] unfurl installation is done !")

    print("[USEFUL TOOLS] anew installation in progress ...")
    os.system('go install github.com/tomnomnom/anew@latest > /dev/null 2>&1 && ln -s ~/go/bin/anew /usr/local/bin/')
    print("[USEFUL TOOLS] anew installation is done !")

    print("[USEFUL TOOLS] gron installation in progress ...")
    os.system('go install github.com/tomnomnom/gron@latest > /dev/null 2>&1 && ln -s ~/go/bin/gron /usr/local/bin/')
    print("[USEFUL TOOLS] gron installation is done !")

    print("[USEFUL TOOLS] qsreplace installation in progress ...")
    os.system('go install github.com/tomnomnom/qsreplace@latest > /dev/null 2>&1 && ln -s ~/go/bin/qsreplace /usr/local/bin/')
    print("[USEFUL TOOLS] qsreplace installation is done !")

    print("[USEFUL TOOLS] Interlace installation in progress ...")
    os.system('cd /root/Tools//ALLInOne/tools && git clone https://github.com/codingo/Interlace.git > /dev/null 2>&1 && cd Interlace && python3 setup.py install > /dev/null 2>&1')
    print("[USEFUL TOOLS] Interlace installation is done !")

    print("[USEFUL TOOLS] jq installation in progress ...")
    os.system('apt-install install -y jq > /dev/null 2>&1')
    print("[USEFUL TOOLS] jq installation is done !")

    print("[USEFUL TOOLS] cf-check installation in progress ...")
    os.system('go install github.com/dwisiswant0/cf-check@latest > /dev/null 2>&1 && ln -s ~/go/bin/cf-check /usr/local/bin/')
    print("[USEFUL TOOLS] cf-check installation is done !")

    print("[USEFUL TOOLS] Tmux installation in progress ...")
    os.system('apt-install install tmux -y > /dev/null 2>&1')
    print("[USEFUL TOOLS] Tmux installation is done !")

    print("[USEFUL TOOLS] Uro installation in progress ...")
    os.system('pip3 install uro > /dev/null 2>&1')
    print("[USEFUL TOOLS] Uro installation is done !")

if __name__ == "__main__":
    main()
