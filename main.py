#!/usr/bin/env python3

import sys
import argparse
import requests
from bs4 import BeautifulSoup
from prettytable import PrettyTable

# some colors
RESET = "\x1b[39m"
CYAN = "\x1b[36m"
LIGHTBLUE = "\x1b[94m"
RED = "\x1b[31m"
LIGHTRED = "\x1b[91m"
YELLOW = "\x1b[33m"
LIGHTYELLOW = "\x1b[93m"
GREEN = "\x1b[32m"
MAGENTA = "\x1b[35m"
WHITE = "\x1b[37m"
LIGHTWHITE = "\x1b[97m"


def console_log(string: str, mode: str):
    last_string = ""
    if mode == "x":
        last_string += f"{CYAN}[{RED}x{CYAN}] "

    elif mode == "H":
        last_string += f"{CYAN}[{LIGHTRED}H{CYAN}] "

    elif mode == "M":
        last_string += f"{CYAN}[{YELLOW}M{CYAN}] "

    elif mode == "i":
        last_string += f"{YELLOW}[{CYAN}i{YELLOW}]{CYAN} "

    else:
        last_string += f"{CYAN}[{MAGENTA}{mode}{CYAN}] "

    last_string += string
    print(last_string)


def is_link(string: str) -> bool:
    if string.lower().startswith("/vuln"):
        return True

    return False


def mix(a, b):
    return a+": "+b+"\n"


def mix_cvss(header, body):
    return f"{header}: {body}\n"


def bar(score: float):
    score = int(score*10)
    print(f"{CYAN}|"+GREEN+'#'*score+" "*(100-score)+RESET +
          f"{CYAN}| ("+GREEN+str(score)+f"%{CYAN}){RESET}")


def search_link(link: str):
    URL = "https://snyk.io"+link
    console_log(f"URL: {URL}", "i")
    try:
        resp = requests.get(URL)
    except requests.exceptions.ConnectionError:
        console_log("Connection error: Failed to reach URL! Exiting...", "x")
        return

    soup = BeautifulSoup(resp.content, "html.parser")
    result = soup.find(id="main")

    title = result.find("h1", class_="header__title")

    # Print title
    affecting = ''.join(i.strip()+":" for i in title.find('p',
                        class_="header__lede").text.split('\n'))[:-1]
    print(f"{title.find('span', class_='header__title__text').text.strip()}\n{affecting}")
    overview = result.find_all("div", class_="card__content")[1]
    ul = overview.find("ul")
    link_list = []
    for links in ul.find_all("a"):
        link_list.append(links.attrs['href'])

    ov = overview.text.split("References")[1].strip().split("\n")

    # References:
    references = "References:\n"+''.join(list(map(mix, ov, link_list)))

    cvss_stuff = result.find("div", class_="cvss-breakdown")

    if cvss_stuff is None:
        console_log("Nothing found", "x")

    cvss_score = cvss_stuff.find(
        "div", class_="cvss-breakdown__score cvss-breakdown__score--critical")
    cvss_score_classes = ["high", "medium", "low"]

    for cvss_score_class in cvss_score_classes:
        while cvss_score is None:
            cvss_score = cvss_stuff.find(
                "div", class_=f"cvss-breakdown__score cvss-breakdown__score--{cvss_score_class}")

    cvss_score = cvss_score.text.strip()
    severity = cvss_stuff.find(
        "div", class_="cvss-breakdown__labels").text.strip()
    cvss_ul = cvss_stuff.find("ul", class_="cvss-breakdown__items")
    headers = cvss_ul.find_all("div", class_="cvss-breakdown__title")
    bodies = cvss_ul.find_all("div", class_="cvss-breakdown__desc")

    headers_list = []
    for header in headers:
        headers_list.append(header.text.strip())

    bodies_list = []
    for body in bodies:
        bodies_list.append(body.text.strip())

    info = LIGHTBLUE+''.join(list(map(mix_cvss, headers_list, bodies_list)))
    attack_vector = info.split("Attack Vector: ")[1].split("\n")[0]
    info = f"{CYAN}{attack_vector}{LIGHTBLUE}".join(info.split(attack_vector))

    if "Critical" in info:
        info = f'{RED}Critical{LIGHTBLUE}'.join(info.split("Critical"))

    elif "High" in info:
        info = f'{LIGHTRED}High{LIGHTBLUE}'.join(info.split("High"))

    elif "Medium" in info:
        info = f'{YELLOW}Medium{LIGHTBLUE}'.join(info.split("Medium"))

    elif "Unchanged" in info:
        info = f'{RED}Unchanged{LIGHTBLUE}'.join(info.split("Unchanged"))

    elif "Low" in info:
        info = f'{LIGHTYELLOW}Low{LIGHTBLUE}'.join(info.split("Low"))

    elif "None" in info:
        info = f'{WHITE}None{LIGHTBLUE}'.join(info.split("None"))

    print(overview.text.split("References")[0]+"\n")
    print(references)
    print()

    cvss_score = float(cvss_score)

    if cvss_score > 8:
        print(
            f"CVSS_Score: {RED}{cvss_score}{' '* (98-len('CVSS_Score: '))}{severity}")

    elif cvss_score > 5 and cvss_score < 8:
        print(
            f"CVSS_Score: {LIGHTRED}{cvss_score}{' '* (98-len('CVSS_Score: '))}{severity}")

    elif cvss_score == 5:
        print(
            f"CVSS_Score: {YELLOW}{cvss_score}{' '* (98-len('CVSS_Score: '))}{severity}")

    elif cvss_score < 5 and cvss_score > 3:
        print(
            f"CVSS_Score: {LIGHTYELLOW}{cvss_score}{' '* (98-len('CVSS_Score: '))}{severity}")

    else:
        print(
            f"CVSS_Score: {WHITE}{cvss_score}{' '* (98-len('CVSS_Score: '))}{severity}")

    bar(cvss_score)
    print()
    print(info)


def main(search_str: str, type: str = "", link: bool = False):

    print(f"""{GREEN} ____              _                            _
/ ___| _ __  _   _| | _____  ___  __ _ _ __ ___| |__
\___ \| '_ \| | | | |/ / __|/ _ \/ _` | '__/ __| '_ \
 ___) | | | | |_| |   <\__ \  __/ (_| | | | (__| | | |
|____/|_| |_|\__, |_|\_\___/\___|\__,_|_|  \___|_| |_|
             |___/
{RESET}""")

    if is_link(search_str):
        search_link(search_str)
        return

    if type and type != "any":
        URL = f"https://snyk.io/vuln/{type}:{search_str}"

    else:
        URL = f"https://snyk.io/vuln/search?q={search_str}&type=any"

    console_log(URL, "i")

    try:
        response = requests.get(URL)

    except requests.exceptions.ConnectionError:
        console_log("Connection error: Failed to reach URL! Exiting...", "x")
        return

    except Exception as e:
        console_log(
            f"An error occoured:\n{e}\nPlease feel free to report the problem at https://github.com/TralseDev/snyksearch/issues\nExiting Program...", "x")
        return

    soup = BeautifulSoup(response.content, "html.parser")

    result = soup.find(id="main")
    table_element = result.find("table", class_="table--comfortable")

    if table_element is None:
        console_log("Nothing found", "x")
        return

    thead_element = table_element.find("thead")
    header = []
    for th in thead_element:
        try:
            head = th.text.split('\n')
            for h in head:
                if len(h.strip()) > 0:
                    header.append(h.strip())
        except:
            pass

    tbody_element = table_element.find("tbody")
    tr_elements = tbody_element.find_all("tr")

    if tr_elements is None:
        console_log("Nothing found", "x")
        return

    lines = []

    len_of_vuln = 0

    for tr in tr_elements:
        vulnerability = tr.find_all("strong")[0].text.strip()
        application = tr.find(
            "strong", class_="list-vulns__item__package__name").find("a").text.strip()

        if len(vulnerability) > len_of_vuln:
            len_of_vuln = len(vulnerability)

        m = tr.find(
            "span", class_="severity-list__item-text").text.strip()

        if m == "H":
            m = f"{CYAN}[{LIGHTRED}H{CYAN}] "

        elif m == "C":
            m = f"{CYAN}[{RED}C{CYAN}] "

        elif m == "M":
            m = f"{CYAN}[{YELLOW}M{CYAN}] "

        else:
            m = f"{CYAN}[{MAGENTA}{m}{CYAN}] "

        if not link:
            lines.append([m+vulnerability, application, tr.find_all("td", class_="t--sm")
                          [1].text.strip(), tr.find("td", class_="l-align-right t--sm").text.strip()])

        else:
            report_link = tr.find_all("a")[0].attrs["href"]
            lines.append([m+vulnerability+f" ({report_link})", application, tr.find_all("td", class_="t--sm")
                          [1].text.strip(), tr.find("td", class_="l-align-right t--sm").text.strip()])

    my_table = PrettyTable(header)
    for i in lines:
        for a in i:
            b = lines[lines.index(i)][i.index(a)+1]
            c = lines[lines.index(i)][i.index(a)+2]
            d = lines[lines.index(i)][i.index(a)+3]
            my_table.add_row([a, b, c, d])
            break

    print(my_table)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="This is snyksearch. A tool which searchs for vulnerability using snyk.")
    parser.add_argument("-s", "--search-for", type=str,
                        help="Application to search for", required=True)
    parser.add_argument("-t", "--type", type=str,
                        help="Type to search for. Available types: cocoapods, composer, go, hex, linux, maven, npm, nuget, pip, rubygems. Type is 'any' if nothing is given", required=False)
    group1 = parser.add_mutually_exclusive_group(required=False)
    group1.add_argument("--link", action="store_true",
                        help="Print report's link")
    args = parser.parse_args()

    type = ""

    if not args.type:
        type = "any"

    else:
        type = args.type

    main(args.search_for, type, args.link)
