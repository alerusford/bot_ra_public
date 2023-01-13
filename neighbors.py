import sys

import aiohttp
import asyncio
import nmap

async def main():
    nm = nmap.PortScanner()
    session = aiohttp.ClientSession()
    if len(sys.argv) > 1:
        searching_dev_id = set(sys.argv[1:])
    else:
        searching_dev_id = {}
    hosts_list = [(x, nm[x]) for x in nm.all_hosts()]
    nm.scan(hosts='192.168.224.0/20', arguments='-T5 -n --max-parallelism=1000 --min-parallelism=500 -sn')
    hosts_list += [(x, nm[x]) for x in nm.all_hosts()]
    tasks = []
    all_data = {}
    answer = {}
    neighbors_search = {}
    for host, host_status in hosts_list:
        if host == "192.168.251.1" or host == "192.168.250.1":
            continue
        tasks.append(asyncio.ensure_future(request_wb_info(host, 15, session)))
    if len(tasks):
        finished, unfinished = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
        for task in finished:
            dev_id, data = task.result()
            answer[dev_id] = data
            for n_dev_id in data["neighbors"]:
                if n_dev_id not in neighbors_search:
                    neighbors_search[n_dev_id] = {dev_id}
                else:
                    neighbors_search[n_dev_id].add(dev_id)
    await session.close()
    additional_dev_ids = set()
    # print(color.BOLD + "MAIN SEARCH" + color.END)
    found = False
    no_ovpn_ip = set()
    iterate = answer
    bad_b_ip = set()
    same_b_ip = {}
    if len(searching_dev_id):
        iterate = searching_dev_id
    for dev_id in iterate:
        if dev_id in neighbors_search:
            additional_dev_ids.update(neighbors_search[dev_id])
        if dev_id in answer:
            data = answer[dev_id]
            neighbors = answer[dev_id]["neighbors"]
            if not len(neighbors):
                neighbors_p = "нет_соседей"
            else:
                neighbors_p = ''
                # neig = []
            for n_dev_id in neighbors:
                neighbor = neighbors[n_dev_id]
                n_host = "unknown"
                if n_dev_id in answer:
                    n_host = answer[n_dev_id]["host"]
                else:
                    no_ovpn_ip.add(n_dev_id)
                if "192.168.201.1:" in neighbor['host']:
                    bad_b_ip.add(n_dev_id)
                if neighbor['host'] not in same_b_ip:
                    same_b_ip[neighbor['host']] = {n_dev_id}
                else:
                    same_b_ip[neighbor['host']].add(n_dev_id)
                neighbors_p += n_host + ' ' + neighbor['reg_num'] + ' ' + n_dev_id + ' ' + str(neighbor['distance']) + 'm' + ' '

            print(data["host"], data["reg_num"], dev_id, neighbors_p)

async def request_wb_info(host, timeout=15, session=None):
    data = {"host": host, "reg_num": None, "type": None, "neighbors": {}}
    dev_id = None
    if session is None:
        session = aiohttp.ClientSession()
    try:
        async with session.get("http://%s:9194/get/device_info" % host, timeout=timeout) as resp:
            answer = await resp.json(content_type=None)
            status = answer["result"]
        dev_id = status.get("device_id", None)
        data["reg_num"] = status.get("reg_num", None)
        data["type"] = status.get("type", None)
        async with session.get("http://%s:9194/get/neighbors" % host, timeout=timeout) as resp:
            answer = await resp.json(content_type=None)
            neighbors = answer["result"]
            for type_ in neighbors:
                if len(neighbors[type_]):
                    for obj in neighbors[type_]:
                        data["neighbors"][obj['device_id']] = {"distance": round(obj['distance']),
                                                               "type": obj['type'],
                                                               "reg_num": obj['reg_num'],
                                                               "host": obj['host']}
    except Exception as e:
        pass
    return dev_id, data


loop = asyncio.get_event_loop()
loop.run_until_complete(main())