#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import os
from bs4 import BeautifulSoup
from urllib.parse import urlencode, quote_plus


async def getBody(client, url: str) -> (int, str, str):
    """
    Get the response body asynchronously.
    Returns a tuple of the status code and the response body.
    """
    try:
        print(f"[-] GET {url}")
        async with client.get(url, timeout=5) as response:
            return (response.status, url, await response.text())
    except:
        return None
    return None


async def createWorkers(lock, queue, urls):
    """
    Creates worker tasks that query given URLs
    """
    async with lock:
        async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)) as client:
            for url in urls:
                response = await getBody(client, url)
                if response and response[0] == 200:
                    await queue.put((response[1], response[2]))


def findFormFields(response: str) -> dict:
    """
    Attempts to find a form field in given html.
    Then attempts to parse the form for username and password
    fields, then returns all given fields in a dict
    """
    soup = BeautifulSoup(response, features="html.parser")
    formField, userField, passField = None, None, None
    results = {"other": []}
    for form in soup.findAll("form"):
        if userField and passField:
            break
        formField = form.get("action")
        inputs = form.findAll("input")
        for inp in inputs:
            if inp.get("type") == "password":
                passField = inp.get("name")
            elif any(x in inp.get("name").lower() for x in ["mail",
                                                            "name",
                                                            "user"]):
                userField = inp.get("name")
            else:
                results["other"].append((inp.get("name"), inp.get("value")))

    if formField and userField and passField:
        results["form"] = formField
        results["user"] = userField
        results["pass"] = passField
        return results
    return None


async def createPatators(tasks, userList, passList, results):
    """
    Awaits asynchronous queue and then parses response bodies
    If a username/password form is found, creates a patator command
    """
    while True:
        response = await tasks.get()
        url = response[0]
        result = findFormFields(response[1])
        if result:
            other = "&".join(
                [urlencode({x: y}, quote_via=quote_plus)
                 for (x, y) in result["other"]])
            results.append(
                f"patator http_fuzz url={url + '/' + result['form']} "
                f"method=POST "
                f"body='{result['user']}=FILE0&{result['pass']}=FILE1"
                f"&{other}' 0={userList} 1={passList} follow=1"
                f" accept_cookie=1 -x ignore:fgrep 'invalid|error|fail'")
        print(f"[+] Processed {url}")
        tasks.task_done()


async def main(targets, userList, passList, outFile):
    """
    Creates and starts async publishers, consumers
    Creates a semaphore to limit the number of requests
    """
    urls = []
    if os.path.isfile(targets):
        with open(targets, 'r') as f:
            for line in f:
                urls.append(line.strip())
    else:
        urls.append(targets)

    lock = asyncio.Semaphore(10)  # Set concurrent task limit
    taskQueue = asyncio.Queue()
    results = []
    consumer = asyncio.create_task(createPatators(
        taskQueue, userList, passList, results))

    await createWorkers(lock, taskQueue, urls)
    await taskQueue.join()
    consumer.cancel()

    with open(outFile, 'w') as f:
        for result in results:
            f.write(result + '\n')
    print(f"[+] Results written to {outFile}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Creates http_fuzz patator commands by "
                                     "identifiying form fields in given URLs")
    parser.add_argument("-u", "--urls", required=True,
                        help="A single URL or file of URLs")
    parser.add_argument(
        "-n", "--name-list", default="usernames.txt",
        help="List of usernames to brute")
    parser.add_argument(
        "-p", "--pass-list", default="passwords.txt",
        help="List of passwords to brute")
    parser.add_argument("-o", "--out-file",
                        default="salad.sh",
                        help="File to write patator commands to,"
                        " defaults to salad.sh in the current directory")
    args = parser.parse_args()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        main(args.urls, args.name_list, args.pass_list, args.out_file))
    loop.close()
