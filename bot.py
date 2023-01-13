import requests
import json
import subprocess
import threading
import time
import traceback
import telebot
import config
import random
import paramiko
import os
from telebot import types
from telebot import util
from telebot import formatting
from save_thread_result import ThreadWithResult
import sys
from paho.mqtt import client as mqtt_client
import httplib2
import apiclient.discovery
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
from os.path import getctime
from datetime import datetime as dt

thisFile = os.path.abspath(__file__)
print(' - path: ', thisFile)

if thisFile == config.this_is_server:
    bot = telebot.TeleBot(config.TOKEN_SERVER)
    config.temp_dir = config.temp_dir_server
    config.file_neighbors_txt = config.file_neighbors_txt_server
    config.file_200_txt = config.file_200_txt_server
    config.credentials_json_for_google = config.credentials_json_for_google_server
    config.file_error_log = config.file_error_log_server

elif thisFile == config.this_is_docker:
    bot = telebot.TeleBot(config.TOKEN)
    config.temp_dir = config.temp_dir_docker
    config.file_neighbors_txt = config.file_neighbors_txt_docker
    config.file_200_txt = config.file_200_txt_docker
    config.credentials_json_for_google = config.credentials_json_for_google_docker
    config.file_error_log = config.file_error_log_docker

    
else:
    if thisFile == config.this_is_home_test:
        bot = telebot.TeleBot(config.TOKEN_TEST)
    elif thisFile == config.this_is_home:
        bot = telebot.TeleBot(config.TOKEN)

    import pandas
    import logging
    from flask import Flask, request

    config.temp_dir = config.temp_dir_home
    config.file_neighbors_txt = config.file_neighbors_txt_home
    config.file_200_txt = config.file_200_txt_home
    config.credentials_json_for_google = config.credentials_json_for_google_home
    config.file_error_log = config.file_error_log_home
    # logging.basicConfig(level=logging.DEBUG)
    # bot = AsyncTeleBot(config.TOKEN)


@bot.message_handler(commands=['start'])
def welcome(message):
    if message.from_user.username in config.users or config.admins:
        bot.send_message(message.chat.id, "Привет, {0.first_name}!".format(message.from_user, bot.get_me()), parse_mode='html')

        bot.send_message(
            message.chat.id,
            formatting.format_text(
                formatting.hbold(message.from_user.first_name),
                formatting.hitalic(message.from_user.first_name),
                formatting.hunderline(message.from_user.first_name),
                formatting.hstrikethrough(message.from_user.first_name),
                formatting.hcode(message.from_user.first_name),
                separator=" "
            ),
            parse_mode='HTML'
        )
    else:
        bot.send_message(message.chat.id, 'в доступе отказано')

# NMAP сканер с соседями, рег_нум, и дев_ид
def scan_neighbors_auto():
    sys.setrecursionlimit(100000)
    date_start = datetime.now()
    print(' - сканирую ... ', date_start)
    try:
        sys.setrecursionlimit(100000)
        if thisFile == config.this_is_server:
            scan_neighbors = subprocess.run(['python3', '/root/bot/neighbors.py'], stdout=subprocess.PIPE)
        elif thisFile == config.this_is_docker:
            scan_neighbors = subprocess.run(['python3', '/bot_ra/neighbors.py'], stdout=subprocess.PIPE)
        else:
            scan_neighbors = subprocess.run(['sudo', 'python3', config.nmap_py], stdout=subprocess.PIPE)
        result_scan_neighbors = scan_neighbors.stdout.decode('utf-8')
        fopen = open(config.file_neighbors_txt, mode='w', encoding='utf8')
        fopen.write(result_scan_neighbors)
        fopen.close()
        date_end = datetime.now()
        print(' - отсканировано за', date_end - date_start, '\n')
        hour_now = str(datetime.now().hour)
        if hour_now in config.times_night:
            time.sleep(config.time_scan_neighbors_nigth)
            scan_neighbors_auto()
        else:
            time.sleep(config.time_scan_neighbors)
            scan_neighbors_auto()
    except RecursionError:
        print(' - RecursionError - ')
        traceback_error_string = traceback.format_exc()
        print("\r\n\r\n" + time.strftime("%c") + "\r\n<<SCANNER>>\r\n" + traceback_error_string + "\r\n<<SCANNER>>")

        with open(config.file_error_log, "a") as myfile:
            myfile.write(
                "\r\n\r\n" + time.strftime("%c") + "\r\n<<SCANNER>>\r\n" + traceback_error_string + "\r\n<<SCANNER>>")
        scan_neighbors_auto_thread = threading.Thread(target=scan_neighbors_auto, name='scanner', args=[])
        scan_neighbors_auto_thread.start()

    except Exception:
        print(' - traceback Exception: ', traceback.format_exc())
        traceback_error_string = traceback.format_exc()
        print("\r\n\r\n" + time.strftime("%c") + "\r\n<<SCANNER>>\r\n" + traceback_error_string + "\r\n<<SCANNER>>")

        with open(config.file_error_log, "a") as myfile:
            myfile.write("\r\n\r\n" + time.strftime(
                "%c") + "\r\n<<SCANNER>>\r\n" + traceback_error_string + "\r\n<<SCANNER>>")
        scan_neighbors_auto_thread = threading.Thread(target=scan_neighbors_auto, name='scanner', args=[])
        scan_neighbors_auto_thread.start()

# функция NMAP сканера адресов 10.200
def scan_200():
    scan200 = subprocess.run(['sudo', 'python3', 'tg_nmap_10.200.py'], stdout=subprocess.PIPE)
    output200 = scan200.stdout
    output200 = output200.decode('utf-8')
    print(output200)
    with open(config.file_200_txt, 'a', encoding='utf8') as update:
        update.write(output200)
        update.close()

def connect_mqtt(broker) -> mqtt_client:
    try:
        port = 1883
        client_id = f'tg_bot-mqtt-{random.randint(0, 100)}'
        username = config.wirenboard_username
        password = config.wirenboard_password

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                print("Connected to MQTT Broker!")
            else:
                print("Failed to connect, return code %d\n", rc)

        client = mqtt_client.Client(client_id)
        client.username_pw_set(username, password)
        client.on_connect = on_connect
        client.connect(broker, port)
        return client
    except TimeoutError:
        print('\n --- TimeoutError !\n')
        return TimeoutError
    except Exception:
        print('\n --- Exception в connect_mqtt(): ', traceback.format_exc(), '\n')

def ping_function(message, ip):
    response = os.system("ping -s 32 -c 1 " + ip)
    return response

def auto_watch_function(var, message, info):
    print('auto watch_function: ', var, ' | info: ', info)

    sys.setrecursionlimit(config.time_setrecursionlimit)

    try:
        fopen = open(config.file_neighbors_txt, mode='r+', encoding='utf8')
        fread = fopen.readlines()
        fopen.close()

        for lines in fread:
            line = lines.split()
            line = line[0:3]

            if var in line:
                result = line
                result_ip = result[0]
                reg_num = result[1]
                function_ping = str('function_ping ' + result_ip + ' ' + reg_num)
                sleep = str('sleep ' + result_ip + ' ' + reg_num)
                message_tg = f'{info}\n - отслежено:\n{line[0]} {line[1]} {line[2]}'
                print('\nотслежено в хостах: ', message_tg, '\n')

                keyboard4 = types.InlineKeyboardMarkup()
                callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

                if message.chat.username in config.users:
                    keyboard4.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.send_message(chat_id=message.chat.id, text=message_tg, reply_markup=keyboard4)
                elif message.chat.username in config.admins:
                    keyboard4.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.send_message(chat_id=message.chat.id, text=message_tg, reply_markup=keyboard4)
                else:
                    print('error')
                break
        else:
            time.sleep(config.time_watch)
            auto_watch_function(var, message, info)
    except RecursionError:
        print(f' - наблюдение за {var} | {message.chat.username} - окончено.')

# ssh client
def ssh_connect(device, username, password, command, timeout_connect, timeout_command):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(device, username=username, password=password, timeout=timeout_connect) # таймаут коннекта
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout_command) # таймаут ответа
        print('device: ', device, 'command: ', command)
        result_paramiko = stdout.readlines()
        print('result in paramiko: ', result_paramiko)
        ssh.close()
        return result_paramiko
    except TimeoutError:
        ssh.close()
        print('\n - ssh connect to ', device, '- TimeoutError\n')
        return TimeoutError
    except paramiko.ssh_exception.SSHException:
        ssh.close()
        print('\n - ssh connect to ', device, '- paramiko.ssh_exception.SSHException\n')
        return TimeoutError

# google sheets
def google_sheets_read(spreadsheet_id, range_var, major):
    CREDENTIALS_FILE = config.credentials_json_for_google
    # read
    credentials = ServiceAccountCredentials.from_json_keyfile_name(
        CREDENTIALS_FILE,
        ['https://www.googleapis.com/auth/spreadsheets',
         'https://www.googleapis.com/auth/drive'])
    httpAuth = credentials.authorize(httplib2.Http())
    service = apiclient.discovery.build('sheets', 'v4', http=httpAuth)
    sheet = service.spreadsheets()
    result = sheet.values().get(spreadsheetId=spreadsheet_id, range=range_var, majorDimension=major).execute()
    values = result.get('values', [])
    if not values:
        print('No data found.')
        return
    for row in values:
        return values

# hubex parser
def hubex_parser_auto(message):

    try:
        session = requests.Session()
        def hubex_authz():
            data = {'serviceToken': config.hubex_service_token}
            authz = session.post('https://api.hubex.ru/fsm/AUTHZ/AccessTokens', json=data)
            token = authz.json()['access_token']
            print(' - token: ', token)
            auth = {'Authorization': 'Bearer ' + token, 'X-APPLICATION-ID': '5'}
            params = {"tenantID": 335, "tenantMemberID": 14}
            authz = session.post('https://api.hubex.ru/fsm/AUTHZ/accounts/authorize/', headers=auth,
                                 json=params)
            token2 = authz.json()['access_token']
            print(' - access_token_JWT:', token2)
            return token2

        def hubex_refresh_token_post():
            access_token_JWT = hubex_authz()
            refresh_header = {'authorization': 'Bearer ' + access_token_JWT, 'X-APPLICATION-ID': '5'}
            json = {"validity": "999"}
            refresh = session.post('https://api.hubex.ru/fsm/AUTHZ/RefreshTokens', headers=refresh_header,
                                   json=json)
            refresh_token = refresh.json()['refresh_token']
            print(' - refresh_token:', refresh_token)
            return refresh_token

        session2 = requests.Session()

        refresh_token_old = hubex_refresh_token_post()

        def new_refresh_token():
            params = {"refreshJwt": refresh_token_old}
            authz = session2.post('https://api.hubex.ru/fsm/AUTHZ/AccessTokens', json=params)
            token2 = authz.json()['access_token']
            print(' - new_access_token_JWT:', token2)
            return token2

        # def parser_messages():
        #     refresh_token = new_refresh_token()
        #     auth2 = {'authorization': 'Bearer ' + refresh_token, 'X-APPLICATION-ID': '5'}
        #     # json = {"isRead": "true"}
        #     response = session2.get('https://api.hubex.ru/fsm/WORK/taskConversations?isRead=false', headers=auth2)
        #     # response = session2.get('https://api.hubex.ru/fsm/WORK/TaskConversations', headers=auth2)
        #     all_msgs_data = response.text
        #     # print()
        #     # print(all_msgs_data)
        #     # print()
        #     if len(all_msgs_data) > 0:
        #         return all_msgs_data
        #     else:
        #         return None

        def parser_data():
            try:
                refresh_token = new_refresh_token()
                auth2 = {'authorization': 'Bearer ' + refresh_token, 'X-APPLICATION-ID': '5'}
                response = session2.get(
                    'https://api.hubex.ru/fsm/WORK/Tasks/?fetch=100&assignedTo=14&isClosed=false&isDeleted=false&offset=0&orderBy=1&searchText=&sortDirection=2&taskStageID=1&taskStageID=4&taskStageID=8&taskStageID=12&taskStageID=13&taskStageID=14&taskStageID=15&taskStageID=19',
                    headers=auth2)
                all_tickets_data = response.text
                employee_data = json.loads(all_tickets_data)
                all_tickets_base = []
                for x in employee_data.values():
                    one_ticket = x['number'], x['asset']['name'], x['notes'], x['taskStatus']['name']
                    all_tickets_base.append(one_ticket)
                return all_tickets_base
            except json.decoder.JSONDecodeError:
                print(response.text)
                print(response)
                pass

        old_data_dict = ''
        try:
            old_data = parser_data()
        except json.decoder.JSONDecodeError:
            time.sleep(1)
            old_data = parser_data()
        if old_data != None:
            for ticket in old_data:
                ticket_theme = ticket[2]
                ticket_reg_num = ticket[1]
                ticket_status = ticket[3]
                print(ticket_theme, '|', ticket_reg_num, '|', ticket_status)

                def neighbors_host():
                    with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
                        data = file.readlines()
                        for line in data:
                            all_result_line = line.split()
                            tachka = all_result_line[0:3]
                            if ticket_reg_num in str(tachka):
                                return tachka

                def neighbors_broadcast():
                    with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
                        data = file.readlines()
                        soseds = []

                        for line in data:
                            all_result_line = line.split()
                            neig = all_result_line[3:]
                            sosed = all_result_line[0:3]

                            neig1 = neig[0:4]
                            neig2 = neig[4:8]
                            neig3 = neig[8:12]
                            neig4 = neig[12:16]
                            neig5 = neig[16:20]

                            if ticket_reg_num in neig1:
                                result = neig1 + sosed
                                soseds.append(result)
                            elif ticket_reg_num in neig2:
                                result = neig2 + sosed
                                soseds.append(result)
                            elif ticket_reg_num in neig3:
                                result = neig3 + sosed
                                soseds.append(result)
                            elif ticket_reg_num in neig4:
                                result = neig4 + sosed
                                soseds.append(result)
                            elif ticket_reg_num in neig5:
                                result = neig5 + sosed
                                soseds.append(result)

                        print(' --- soseds: --- ', soseds)
                        return soseds
                def fread200():
                    with open(config.file_200_txt, 'r', encoding='utf8') as fopen200:
                        fread200_file = fopen200.readlines()
                        for line in fread200_file:
                            if ticket_reg_num in line:
                                return line

                host = neighbors_host()
                b_host = neighbors_broadcast()
                fread_return = fread200()

                if host == None and b_host == [] and fread_return == None:
                    var = ticket_reg_num
                    info = str(ticket_theme + ' | ' + ticket_reg_num)
                    threadname = str('watch_auto ' + ticket_reg_num + ' | ' + message.from_user.username)
                    threading.Thread(target=auto_watch_function, name=threadname, args=[var, message, info]).start()
                    bot.send_message(message.chat.id,
                                     f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n - слежу за {ticket_reg_num}.')

                elif host:
                    if fread_return == None:
                        ip_198 = host[0]
                        reg_num_198 = host[1]
                        dev_id_198 = host[2]
                        function_ping = str('function_ping ' + ip_198 + ' ' + reg_num_198)
                        sleep = str('sleep ' + ip_198 + ' ' + reg_num_198)
                        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                        keyboard = types.InlineKeyboardMarkup()
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_198} {reg_num_198} {dev_id_198}',
                                         reply_markup=keyboard)
                    elif fread_return:
                        ip_198 = host[0]
                        reg_num_198 = host[1]
                        dev_id_198 = host[2]
                        function_ping = str('function_ping ' + ip_198 + ' ' + reg_num_198)
                        sleep = str('sleep ' + ip_198 + ' ' + reg_num_198)
                        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                        keyboard = types.InlineKeyboardMarkup()
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_198} {reg_num_198} {dev_id_198}\n{fread_return}',
                                         reply_markup=keyboard)

                elif b_host:

                    def function_broadcast_config_create():
                        spreadsheet_id = config.broadcast_spreadsheet_id
                        major = 'ROWS'
                        range_belgorod = 'Белгород!A2:D255'  # 'Sheet2!A2:E10'
                        sheet_broadcats_belgorog = google_sheets_read(spreadsheet_id, range_belgorod, major)
                        range_kursk = 'Курск!A2:D255'
                        sheet_broadcats_kursk = google_sheets_read(spreadsheet_id, range_kursk, major)
                        range_tambov = 'Тамбов!A2:D255'
                        sheet_broadcats_tambov = google_sheets_read(spreadsheet_id, range_tambov, major)
                        range_orel = 'Орел!A2:D255'
                        sheet_broadcats_orel = google_sheets_read(spreadsheet_id, range_orel, major)
                        range_primorie = 'Приморье!A2:D255'
                        sheet_broadcats_primorie = google_sheets_read(spreadsheet_id, range_primorie, major)
                        for row in sheet_broadcats_belgorog:
                            if ticket_reg_num in row:
                                reg_num_from_sheet = row[0]
                                broadcast_ip_from_sheet = row[1]
                                mikrotik_ip = row[2]
                                return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                        for row in sheet_broadcats_kursk:
                            if ticket_reg_num in row:
                                reg_num_from_sheet = row[0]
                                broadcast_ip_from_sheet = row[1]
                                mikrotik_ip = row[2]
                                return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                        for row in sheet_broadcats_tambov:
                            if ticket_reg_num in row:
                                reg_num_from_sheet = row[0]
                                broadcast_ip_from_sheet = row[1]
                                mikrotik_ip = row[2]
                                return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                        for row in sheet_broadcats_orel:
                            if ticket_reg_num in row:
                                reg_num_from_sheet = row[0]
                                broadcast_ip_from_sheet = row[1]
                                mikrotik_ip = row[2]
                                return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                        for row in sheet_broadcats_primorie:
                            if ticket_reg_num in row:
                                reg_num_from_sheet = row[0]
                                broadcast_ip_from_sheet = row[1]
                                mikrotik_ip = row[2]
                                return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                    broadcast_table = 'None'
                    broadcast_table = function_broadcast_config_create()
                    print()
                    print(' - broadcasts: ', broadcast_table)
                    print()



                    if fread_return == None:
                        var = ticket_reg_num
                        info = str(ticket_theme + ' | ' + ticket_reg_num)
                        threadname = str('watch_auto ' + ticket_reg_num + ' | ' + message.from_user.username)
                        threading.Thread(target=auto_watch_function, name=threadname, args=[var, message, info]).start()

                        try:
                            unknown_tachka_ip = b_host[0][0]
                            unknown_tachka_reg_num = b_host[0][1]
                            unknown_tachka_dev_id = b_host[0][2]

                            broadcast_reg_num = broadcast_table.split()[0] or 'None'
                            broadcast_ip = broadcast_table.split()[1] or 'None'
                            broadcast_mikrotik = broadcast_table.split()[2] or 'None'

                            if len(b_host) == 1:
                                bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')

                            elif len(b_host) == 2:
                                bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')

                            elif len(b_host) == 3:
                                bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')

                            elif len(b_host) == 4:
                                bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n{b_host[3][4]} {b_host[3][5]} {b_host[3][6]} | {b_host[3][3]}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')

                            elif len(b_host) >= 5:
                                bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n{b_host[3][4]} {b_host[3][5]} {b_host[3][6]} | {b_host[3][3]}\n{b_host[4][4]} {b_host[4][5]} {b_host[4][6]} | {b_host[4][3]}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')
                            else:
                                print(' - нет условия: ', b_host)
                                bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{b_host}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')

                        except IndexError:
                            bot.send_message(message.chat.id,  f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{b_host}\n - слежу за {ticket_reg_num}. \n - IndexError!!!')

                    elif fread_return:
                        info = str(ticket_theme + ' | ' + ticket_reg_num)
                        threadname = str('watch_auto ' + ticket_reg_num + ' | ' + message.from_user.username)
                        threading.Thread(target=auto_watch_function, name=threadname, args=[ticket_reg_num, message, info]).start()

                        unknown_tachka_ip = b_host[0][0]
                        unknown_tachka_reg_num = b_host[0][1]
                        unknown_tachka_dev_id = b_host[0][2]

                        broadcast_reg_num = broadcast_table.split()[0] or 'None'
                        broadcast_ip = broadcast_table.split()[1] or 'None'
                        broadcast_mikrotik = broadcast_table.split()[2] or 'None'

                        if len(b_host) == 1:
                            bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n\n{fread_return}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')
                        elif len(b_host) == 2:
                            bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n\n{fread_return}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')
                        elif len(b_host) == 3:
                            bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n\n{fread_return}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')
                        elif len(b_host) == 4:
                            bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n{b_host[3][4]} {b_host[3][5]} {b_host[3][6]} | {b_host[3][3]}\n\n{fread_return}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')
                        elif len(b_host) >= 5:
                            bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n{b_host[3][4]} {b_host[3][5]} {b_host[3][6]} | {b_host[3][3]}\n{b_host[4][4]} {b_host[4][5]} {b_host[4][6]} | {b_host[4][3]}\n\n{fread_return}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')
                        else:
                            bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{b_host}\n{fread_return}\nбродкасты:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}\n\n - слежу за {ticket_reg_num}.')

                elif fread_return:
                    data = fread_return.split()
                    ip_200 = data[0]
                    reg_num_200 = data[1]
                    dev_id_200 = data[2]

                    threadname = f"ping_auto {ip_200} | {message.from_user.username}"
                    thread_ping = ThreadWithResult(target=ping_function, name=threadname, args=[message, ip_200])
                    thread_ping.start()
                    thread_ping.join()
                    print('thread.result: ', thread_ping.result)
                    function_ping = str('function_ping ' + ip_200 + ' ' + reg_num_200)
                    sleep = str('sleep ' + ip_200 + ' ' + reg_num_200)
                    function_watch = str('function_watch ' + ticket_reg_num)

                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                    keyboard = types.InlineKeyboardMarkup()

                    if thread_ping.result == 0:
                        print('ping ok!')
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_200} {reg_num_200} {dev_id_200}\n - ping {ip_200} ok!', reply_markup=keyboard)
                    else:
                        print('ping don`t ok')
                        var = ticket_reg_num
                        info = str(ticket_theme + ' | ' + ticket_reg_num)
                        threadname = str('watch_auto ' + ticket_reg_num + ' | ' + message.from_user.username)
                        watch_func = threading.Thread(target=auto_watch_function, name=threadname,
                                                      args=[var, message, info])
                        watch_func.start()
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_200} {reg_num_200} {dev_id_200}\n - ping {ip_200} don`t ok...\n - слежу за {ticket_reg_num}.')

        timer = 0
        while timer < config.hubex_while_close:
            time.sleep(config.hubex_time_parser)
            timer = timer + 1
            print('timer: ', timer)
            old_data_dict = old_data
            new_data = parser_data()
            print(datetime.now())

            if new_data == None:
                print(' - нет тикетов ... ')
                pass

            else:
                if old_data_dict != None:
                    if new_data != None:
                        first_tuple_list = [tuple(lst) for lst in old_data_dict]
                        second_tuple_list = [tuple(lst) for lst in new_data]
                        first_set = set(first_tuple_list)
                        second_set = set(second_tuple_list)
                        result_difference = second_set.symmetric_difference(first_set)
                        print(' - old: ', len(first_set))
                        print(' - new: ', len(second_set))
                        print(' - RESULT SYMMETRIC: ', result_difference)

                        if result_difference == set():
                            print(' - нет разницы')
                        else:
                            for line in result_difference:
                                if line not in first_set:
                                    new_ticket = line
                                    ticket_number = new_ticket[0]
                                    ticket_reg_num = new_ticket[1]
                                    ticket_theme = new_ticket[2]
                                    ticket_status = new_ticket[3]

                                    print('theme: ', ticket_theme)
                                    print('reg_num: ', ticket_reg_num)
                                    print('number: ', ticket_number)
                                    print('status: ', ticket_status)

                                    if ticket_status == 'Новая':
                                        print()
                                        print(' - NEW TICKET!!! - ')
                                        print(ticket_number, ticket_theme, ticket_reg_num, ticket_status)

                                        def search_192():
                                            with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
                                                data = file.readlines()
                                                for line in data:
                                                    all_result_line = line.split()
                                                    tachka = all_result_line[0:3]
                                                    if ticket_reg_num in str(tachka):
                                                        return tachka

                                        def search_200():
                                            with open(config.file_200_txt, 'r', encoding='utf-8') as file:
                                                data200 = file.readlines()
                                                for line in data200:
                                                    if ticket_reg_num in line:
                                                        return line

                                        result_192 = search_192()
                                        result_200 = search_200()
                                        print(' - result_192: ', result_192)
                                        print(' - result_200: ', result_200)

                                        info = str(ticket_theme + ' | ' + ticket_reg_num)
                                        threadname = str('watch_auto ' + ticket_reg_num + ' | ' + message.from_user.username)

                                        if result_192 != None and result_200 == None:
                                            function_ping = str('function_ping ' + result_192[0] + ' ' + result_192[1])
                                            sleep = str('sleep ' + result_192[0] + ' ' + result_192[1])
                                            callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                                            callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                                            callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                                            keyboard = types.InlineKeyboardMarkup()
                                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                            bot.send_message(message.chat.id, f'новый тикет!\n{ticket_theme} | {ticket_reg_num} \n\n{result_192[0]} {result_192[1]} {result_192[2]}', reply_markup=keyboard)

                                        elif result_200 != None and result_192 == None:
                                            ip_200 = result_200.split()[0]
                                            reg_num_200 = result_200.split()[1]
                                            dev_id_200 = result_200.split()[2]
                                            threading.Thread(target=auto_watch_function, name=threadname, args=[ticket_reg_num, message, info]).start()
                                            bot.send_message(message.chat.id, f'новый тикет!\n{ticket_theme} | {ticket_reg_num} \n\n{ip_200} {reg_num_200} {dev_id_200}\n - слежу за {ticket_reg_num}.')

                                        elif result_192 != None and result_200 != None:
                                            function_ping = str('function_ping ' + result_192[0] + ' ' + result_192[1])
                                            sleep = str('sleep ' + result_192[0] + ' ' + result_192[1])
                                            ip_200 = result_200.split()[0]
                                            reg_num_200 = result_200.split()[1]
                                            dev_id_200 = result_200.split()[2]
                                            callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                                            callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                                            callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                                            keyboard = types.InlineKeyboardMarkup()
                                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                            bot.send_message(message.chat.id, f'новый тикет!\n{ticket_theme} | {ticket_reg_num}\n\n{result_192[0]} {result_192[1]} {result_192[2]}\n{ip_200} {reg_num_200} {dev_id_200}', reply_markup=keyboard)

                                        else:
                                            threading.Thread(target=auto_watch_function, name=threadname, args=[ticket_reg_num, message, info]).start()
                                            bot.send_message(message.chat.id, f'новый тикет!\n{ticket_theme} | {ticket_reg_num}\n\n - слежу за {ticket_reg_num}.')

                                    elif ticket_status == 'Новый комментарий Оператора' or ticket_status == 'Повторное уведомление':
                                        print(' - новый коммент - ')
                                        print(ticket_number, ticket_theme, ticket_reg_num, ticket_status)
                                        bot.send_message(message.chat.id, f'новый коммент!\n{ticket_theme} | {ticket_reg_num}')



                                    elif ticket_status == 'Новый комментарий АБМ':
                                        pass

                                    elif ticket_status == 'В работе':
                                        pass

                                    elif ticket_status == 'Решена' or ticket_status == 'Закрыта':
                                        pass

                                    elif ticket_status == 'Недоступно':
                                        pass

                                    elif ticket_status == 'Не выполнена':
                                        pass

                                    elif ticket_status == 'Требуется выезд':
                                        pass

                                    else:
                                        print(' - НЕТ УСЛОВИЯ ! - ')
                                        print(' - new_ticket: ', line)
                                        bot.send_message(message.chat.id,
                                                         f'НЕТ УСЛОВИЯ!\n{ticket_theme} | {ticket_reg_num}\n{ticket_number} | {ticket_status}')
                            print()
                            print('old_data_dict --- : ', old_data_dict)
                            old_data_dict.clear()
                            print('old_data_dict clear: ', old_data_dict)
                            for line in new_data:
                                old_data_dict.append(line)

                            print('old_data_dict new: ', old_data_dict)
                elif old_data_dict == None:
                    if new_data != None:
                        for line in new_data:
                            new_ticket = line
                            ticket_number = new_ticket[0]
                            ticket_theme = new_ticket[1]
                            ticket_reg_num = new_ticket[2]
                            ticket_status = new_ticket[3]

                            print(ticket_theme, ticket_reg_num, ticket_number, ticket_status)

                            if ticket_status == 'Новая':
                                print()
                                print(' - NEW TICKET!!! - ')
                                print(ticket_number, ticket_theme, ticket_reg_num, ticket_status)

                                def search_192():
                                    with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
                                        data192 = file.readlines()
                                        for line in data192:
                                            if ticket_reg_num in line:
                                                return line

                                def search_200():
                                    with open(config.file_200_txt, 'r', encoding='utf-8') as file:
                                        data200 = file.readlines()
                                        for line in data200:
                                            if ticket_reg_num in line:
                                                return line

                                result_192 = search_192()
                                result_200 = search_200()
                                info = str(ticket_theme + ' | ' + ticket_reg_num)
                                threadname = str('watch_auto ' + ticket_reg_num + ' | ' + message.from_user.username)
                                print(' - result_192: ', result_192)
                                print(' - result_200: ', result_200)

                                if result_192 != None and result_200 == None:
                                    function_ping = str('function_ping ' + result_192[0] + ' ' + result_192[1])
                                    sleep = str('sleep ' + result_192[0] + ' ' + result_192[1])
                                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                                    keyboard = types.InlineKeyboardMarkup()
                                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                    bot.send_message(message.chat.id,
                                                     f'новый тикет!\n{ticket_theme} | {ticket_reg_num} \n\n{result_192[0]} {result_192[1]} {result_192[2]}',
                                                     reply_markup=keyboard)

                                elif result_200 != None and result_192 == None:
                                    ip_200 = result_200.split()[0]
                                    reg_num_200 = result_200.split()[1]
                                    dev_id_200 = result_200.split()[2]
                                    threading.Thread(target=auto_watch_function, name=threadname, args=[ticket_reg_num, message, info]).start()
                                    bot.send_message(message.chat.id,
                                                     f'новый тикет!\n{ticket_theme} | {ticket_reg_num} \n\n{ip_200} {reg_num_200} {dev_id_200}\n - слежу за {ticket_reg_num}.')

                                elif result_192 != None and result_200 != None:
                                    function_ping = str('function_ping ' + result_192[0] + ' ' + result_192[1])
                                    sleep = str('sleep ' + result_192[0] + ' ' + result_192[1])
                                    ip_200 = result_200.split()[0]
                                    reg_num_200 = result_200.split()[1]
                                    dev_id_200 = result_200.split()[2]
                                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                                    keyboard = types.InlineKeyboardMarkup()
                                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                    bot.send_message(message.chat.id,
                                                     f'новый тикет!\n{ticket_theme} | {ticket_reg_num}\n\n{result_192[0]} {result_192[1]} {result_192[2]}\n{ip_200} {reg_num_200} {dev_id_200}',
                                                     reply_markup=keyboard)

                                else:
                                    threading.Thread(target=auto_watch_function, name=threadname, args=[ticket_reg_num, message, info]).start()
                                    bot.send_message(message.chat.id, f'новый тикет!\n{ticket_theme} | {ticket_reg_num}\n\n - слежу за {ticket_reg_num}.')


                            elif ticket_status == 'Новый комментарий Оператора' or ticket_status == 'Повторное уведомление':
                                print(' - новый коммент - ')
                                print(ticket_number, ticket_theme, ticket_reg_num, ticket_status)
                                # todo добавить кнопки и адреса
                                bot.send_message(message.chat.id, f'новый коммент!\n{ticket_theme} | {ticket_reg_num}')

                            elif ticket_status == 'Новый комментарий АБМ':
                                pass

                            elif ticket_status == 'В работе':
                                pass

                            elif ticket_status == 'Решена' or ticket_status == 'Закрыта':
                                pass

                            elif ticket_status == 'Недоступно':
                                pass

                            elif ticket_status == 'Не выполнена':
                                pass

                            elif ticket_status == 'Требуется выезд':
                                pass

                            else:
                                print(' - НЕТ УСЛОВИЯ ! - ')
                                print(' - new_ticket: ', line)
                                bot.send_message(message.chat.id,
                                                 f'НЕТ УСЛОВИЯ!\n{ticket_theme} | {ticket_reg_num}\n{ticket_number} | {ticket_status}')
                        print()
                        print('old_data_dict --- : ', old_data_dict)
                        # old_data_dict.clear()
                        print('old_data_dict clear: ', old_data_dict)
                        for line in new_data:
                            old_data_dict.append(line)
        print('the end parser')


    except Exception:
        print(traceback.format_exc())
        bot.send_message(message.chat.id, f'{traceback.format_exc()}')

def hubex_parser_manual(message):
    session = requests.Session()
    def hubex_authz():
        data = {'serviceToken': config.hubex_service_token}
        authz = session.post('https://api.hubex.ru/fsm/AUTHZ/AccessTokens', json=data)
        token = authz.json()['access_token']
        print(' - token: ', token)
        # return token
        auth = {'Authorization': 'Bearer ' + token, 'X-APPLICATION-ID': '5'}
        params = {"tenantID": 335, "tenantMemberID": 14}
        authz = session.post('https://api.hubex.ru/fsm/AUTHZ/accounts/authorize/', headers=auth,
                             json=params)
        token2 = authz.json()['access_token']
        print(' - access_token_JWT:', token2)
        return token2

    def hubex_refresh_token_post():
        access_token_JWT = hubex_authz()
        refresh_header = {'authorization': 'Bearer ' + access_token_JWT, 'X-APPLICATION-ID': '5'}
        json = {"validity": "999"}
        refresh = session.post('https://api.hubex.ru/fsm/AUTHZ/RefreshTokens', headers=refresh_header,
                               json=json)
        refresh_token = refresh.json()['refresh_token']
        print(' - refresh_token:', refresh_token)
        return refresh_token

    session2 = requests.Session()

    refresh_token_old = hubex_refresh_token_post()

    def new_refresh_token():
        params = {"refreshJwt": refresh_token_old}
        authz = session2.post('https://api.hubex.ru/fsm/AUTHZ/AccessTokens', json=params)
        token2 = authz.json()['access_token']
        print(' - new_access_token_JWT:', token2)
        return token2

    def parser_data():
        try:
            refresh_token = new_refresh_token()
            auth2 = {'authorization': 'Bearer ' + refresh_token, 'X-APPLICATION-ID': '5'}
            response = session2.get(
                'https://api.hubex.ru/fsm/WORK/Tasks/?fetch=100&assignedTo=14&isClosed=false&isDeleted=false&offset=0&orderBy=1&searchText=&sortDirection=2&taskStageID=1&taskStageID=4&taskStageID=8&taskStageID=12&taskStageID=13&taskStageID=14&taskStageID=15&taskStageID=19',
                headers=auth2)
            all_tickets_data = response.text
            employee_data = json.loads(all_tickets_data)
            all_tickets_base = []
            for x in employee_data.values():
                one_ticket = x['number'], x['asset']['name'], x['notes'], x['taskStatus']['name']
                all_tickets_base.append(one_ticket)
            return all_tickets_base
        except json.decoder.JSONDecodeError:
            print(response.text)
            print(response)
            # bot.send_message(message.chat.id, ' - нет тикетов!')
            pass

    old_data_dict = ''
    try:
        old_data = parser_data()
    except json.decoder.JSONDecodeError:
        time.sleep(1)
        old_data = parser_data()

    if old_data != None:
        for ticket in old_data:
            ticket_theme = ticket[2]
            ticket_reg_num = ticket[1]
            ticket_status = ticket[3]
            print(ticket_theme, '|', ticket_reg_num, '|', ticket_status)

            def neighbors_host():
                with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
                    data = file.readlines()
                    for line in data:
                        all_result_line = line.split()
                        tachka = all_result_line[0:3]
                        if ticket_reg_num in str(tachka):
                            return tachka

            def neighbors_broadcast():
                with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
                    data = file.readlines()
                    soseds = []

                    for line in data:
                        all_result_line = line.split()
                        neig = all_result_line[3:]
                        sosed = all_result_line[0:3]

                        neig1 = neig[0:4]
                        neig2 = neig[4:8]
                        neig3 = neig[8:12]
                        neig4 = neig[12:16]
                        neig5 = neig[16:20]

                        if ticket_reg_num in neig1:
                            print()
                            print('line: ', line)
                            print('sosed: ', sosed)
                            print('unknown: ', neig1[0], neig1[1], neig1[2], neig1[3])
                            print()
                            result = neig1 + sosed
                            soseds.append(result)
                        elif ticket_reg_num in neig2:
                            print()
                            print('line: ', line)
                            print('sosed: ', sosed)
                            print('unknown: ', neig2[0], neig2[1], neig2[2], neig2[3])
                            print()
                            result = neig2 + sosed
                            soseds.append(result)
                        elif ticket_reg_num in neig3:
                            print()
                            print('line: ', line)
                            print('sosed: ', sosed)
                            print('unknown: ', neig3[0], neig3[1], neig3[2], neig3[3])
                            print()
                            result = neig3 + sosed
                            soseds.append(result)
                        elif ticket_reg_num in neig4:
                            print()
                            print('line: ', line)
                            print('sosed: ', sosed)
                            print('unknown: ', neig4[0], neig4[1], neig4[2], neig4[3])
                            print()
                            result = neig4 + sosed
                            soseds.append(result)
                        elif ticket_reg_num in neig5:
                            print()
                            print('line: ', line)
                            print('sosed: ', sosed)
                            print('unknown: ', neig5[0], neig5[1], neig5[2], neig5[3])
                            print()
                            result = neig5 + sosed
                            soseds.append(result)

                    print(' --- soseds: --- ', soseds)
                    return soseds

                    # if ticket_reg_num in str(neig):
                    #     print(neig)
                    # return sosed

            def fread200():
                with open(config.file_200_txt, 'r', encoding='utf8') as fopen200:
                    fread200_file = fopen200.readlines()
                    for line in fread200_file:
                        if ticket_reg_num in line:
                            return line

            host = neighbors_host()
            b_host = neighbors_broadcast()
            fread_return = fread200()
            # print(ticket_number, '|', ticket_theme, '|', ticket_reg_num)
            print('file host: ', host)
            print('file b_host: ', b_host)
            print('file fread_return: ', fread_return)
            print()

            function_watch = str('function_watch ' + ticket_reg_num)

            if host == None and b_host == [] and fread_return == None:
                sleep = str('sleep ' + 'None' + ' ' + ticket_reg_num)
                callback_button_watch = types.InlineKeyboardButton(text="следить", callback_data=function_watch)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                keyboard = types.InlineKeyboardMarkup()
                keyboard.add(callback_button_watch, callback_button_sleep, callback_button_close)
                bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}', reply_markup=keyboard)

            elif host:
                if fread_return == None:
                    ip_198 = host[0]
                    reg_num_198 = host[1]
                    dev_id_198 = host[2]
                    function_ping = str('function_ping ' + ip_198 + ' ' + reg_num_198)
                    sleep = str('sleep ' + ip_198 + ' ' + reg_num_198)
                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                    keyboard = types.InlineKeyboardMarkup()
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_198} {reg_num_198} {dev_id_198}', reply_markup=keyboard)
                elif fread_return:
                    ip_198 = host[0]
                    reg_num_198 = host[1]
                    dev_id_198 = host[2]
                    function_ping = str('function_ping ' + ip_198 + ' ' + reg_num_198)
                    sleep = str('sleep ' + ip_198 + ' ' + reg_num_198)
                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                    keyboard = types.InlineKeyboardMarkup()
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.send_message(message.chat.id,
                                     f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_198} {reg_num_198} {dev_id_198}\n{fread_return}',
                                     reply_markup=keyboard)

            elif b_host:

                def function_broadcast_config_create():
                    spreadsheet_id = config.broadcast_spreadsheet_id
                    major = 'ROWS'
                    range_belgorod = 'Белгород!A2:D255'  # 'Sheet2!A2:E10'
                    sheet_broadcats_belgorog = google_sheets_read(spreadsheet_id, range_belgorod, major)
                    range_kursk = 'Курск!A2:D255'
                    sheet_broadcats_kursk = google_sheets_read(spreadsheet_id, range_kursk, major)
                    range_tambov = 'Тамбов!A2:D255'
                    sheet_broadcats_tambov = google_sheets_read(spreadsheet_id, range_tambov, major)
                    range_orel = 'Орел!A2:D255'
                    sheet_broadcats_orel = google_sheets_read(spreadsheet_id, range_orel, major)
                    range_primorie = 'Приморье!A2:D255'
                    sheet_broadcats_primorie = google_sheets_read(spreadsheet_id, range_primorie, major)
                    for row in sheet_broadcats_belgorog:
                        if ticket_reg_num in row:
                            reg_num_from_sheet = row[0]
                            broadcast_ip_from_sheet = row[1]
                            mikrotik_ip = row[2]
                            return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                    for row in sheet_broadcats_kursk:
                        if ticket_reg_num in row:
                            reg_num_from_sheet = row[0]
                            broadcast_ip_from_sheet = row[1]
                            mikrotik_ip = row[2]
                            return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                    for row in sheet_broadcats_tambov:
                        if ticket_reg_num in row:
                            reg_num_from_sheet = row[0]
                            broadcast_ip_from_sheet = row[1]
                            mikrotik_ip = row[2]
                            return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                    for row in sheet_broadcats_orel:
                        if ticket_reg_num in row:
                            reg_num_from_sheet = row[0]
                            broadcast_ip_from_sheet = row[1]
                            mikrotik_ip = row[2]
                            return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                    for row in sheet_broadcats_primorie:
                        if ticket_reg_num in row:
                            reg_num_from_sheet = row[0]
                            broadcast_ip_from_sheet = row[1]
                            mikrotik_ip = row[2]
                            return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                broadcast_table = 'None'
                broadcast_table = function_broadcast_config_create()
                print()
                print(' - broadcasts: ', broadcast_table)
                print()

                if fread_return == None:
                    # var = ticket_reg_num
                    # info = str(ticket_theme + ' | ' + ticket_reg_num)
                    # threadname = str('watch_auto ' + ticket_reg_num + ' | ' + message.from_user.username)
                    # threading.Thread(target=auto_watch_function, name=threadname, args=[var, message, info]).start()

                    try:
                        print()
                        print(' - b_host: ', b_host)
                        print(len(b_host))

                        # neig1 = b_host[0:4]
                        # neig2 = b_host[4:8]
                        # neig3 = b_host[8:12]
                        # neig4 = b_host[12:16]
                        # neig5 = b_host[16:20]

                        unknown_tachka_ip = b_host[0][0]
                        unknown_tachka_reg_num = b_host[0][1]
                        unknown_tachka_dev_id = b_host[0][2]

                        broadcast_reg_num = broadcast_table.split()[0] or 'None'
                        broadcast_ip = broadcast_table.split()[1] or 'None'
                        broadcast_mikrotik = broadcast_table.split()[2] or 'None'

                        sleep = str('sleep ' + unknown_tachka_ip + ' ' + unknown_tachka_reg_num)
                        function_watch = str('function_watch ' + unknown_tachka_reg_num)
                        callback_button_watch = types.InlineKeyboardButton(text="следить", callback_data=function_watch)
                        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                        keyboard = types.InlineKeyboardMarkup()
                        keyboard.add(callback_button_watch, callback_button_sleep, callback_button_close)

                        if len(b_host) == 1:
                            bot.send_message(message.chat.id,
                                             f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)

                        elif len(b_host) == 2:
                            bot.send_message(message.chat.id,
                                             f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)

                        elif len(b_host) == 3:
                            bot.send_message(message.chat.id,
                                             f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)

                        elif len(b_host) == 4:
                            bot.send_message(message.chat.id,
                                             f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n{b_host[3][4]} {b_host[3][5]} {b_host[3][6]} | {b_host[3][3]}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)

                        elif len(b_host) >= 5:
                            bot.send_message(message.chat.id,
                                             f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n{b_host[3][4]} {b_host[3][5]} {b_host[3][6]} | {b_host[3][3]}\n{b_host[4][4]} {b_host[4][5]} {b_host[4][6]} | {b_host[4][3]}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)
                        else:
                            print(' - нет условия: ', b_host)
                            bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{b_host}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)

                    except IndexError:
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{b_host}\n\nданные из таблицы:\n\n - IndexError!!!')

                elif fread_return:
                    # info = str(ticket_theme + ' | ' + ticket_reg_num)
                    # threadname = str('watch_auto ' + ticket_reg_num + ' | ' + message.from_user.username)
                    # threading.Thread(target=auto_watch_function, name=threadname, args=[ticket_reg_num, message, info]).start()

                    unknown_tachka_ip = b_host[0][0]
                    unknown_tachka_reg_num = b_host[0][1]
                    unknown_tachka_dev_id = b_host[0][2]

                    broadcast_reg_num = broadcast_table.split()[0] or 'None'
                    broadcast_ip = broadcast_table.split()[1] or 'None'
                    broadcast_mikrotik = broadcast_table.split()[2] or 'None'

                    sleep = str('sleep ' + unknown_tachka_ip + ' ' + unknown_tachka_reg_num)
                    function_watch = str('function_watch ' + unknown_tachka_reg_num)
                    callback_button_watch = types.InlineKeyboardButton(text="следить", callback_data=function_watch)
                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                    keyboard = types.InlineKeyboardMarkup()
                    keyboard.add(callback_button_watch, callback_button_sleep, callback_button_close)

                    if len(b_host) == 1:
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n\n{fread_return}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)
                    elif len(b_host) == 2:
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n\n{fread_return}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)
                    elif len(b_host) == 3:
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n\n{fread_return}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)
                    elif len(b_host) == 4:
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n{b_host[3][4]} {b_host[3][5]} {b_host[3][6]} | {b_host[3][3]}\n\n{fread_return}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)
                    elif len(b_host) >= 5:
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{unknown_tachka_ip} {unknown_tachka_reg_num} {unknown_tachka_dev_id}\n\n{b_host[0][4]} {b_host[0][5]} {b_host[0][6]} | {b_host[0][3]}\n{b_host[1][4]} {b_host[1][5]} {b_host[1][6]} | {b_host[1][3]}\n{b_host[2][4]} {b_host[2][5]} {b_host[2][6]} | {b_host[2][3]}\n{b_host[3][4]} {b_host[3][5]} {b_host[3][6]} | {b_host[3][3]}\n{b_host[4][4]} {b_host[4][5]} {b_host[4][6]} | {b_host[4][3]}\n\n{fread_return}\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)
                    else:
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{b_host}\n{fread_return}\n\nданные из таблицы:\nreg_num: {broadcast_reg_num}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {broadcast_mikrotik}', reply_markup=keyboard)

            elif fread_return:
                data = fread_return.split()
                ip_200 = data[0]
                reg_num_200 = data[1]
                dev_id_200 = data[2]

                function_watch = str('function_watch ' + ticket_reg_num)
                sleep = str('sleep ' + ip_200 + ' ' + reg_num_200)
                callback_button_watch = types.InlineKeyboardButton(text="следить", callback_data=function_watch)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                keyboard = types.InlineKeyboardMarkup()
                keyboard.add(callback_button_watch, callback_button_sleep, callback_button_close)
                bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_200} {reg_num_200} {dev_id_200}', reply_markup=keyboard)

def len_neighbors(reg_num):
    with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
        data = file.readlines()
        his_neighbors = []
        chunked_list = list()

        for line in data:
            all_line = line.split()
            host = all_line[0:3]
            neighbors = all_line[3:]

            if reg_num == host[1]:
                # print(' - хост: ', host)
                if neighbors != ['нет_соседей']:
                    chunk_size = 4
                    for i in range(0, len(neighbors), chunk_size):
                        neig = neighbors[i:i + chunk_size]
                        # print(' - ', neig[0:3])
                        # chunked_list.append(neighbors[i:i + chunk_size])
                        chunked_list.append(neig[0:3])
                    # print(' - он видит: ', chunked_list)
                    # print(' - кол-во соседей: ', len(chunked_list))
                elif neighbors == ['нет_соседей']:
                    # host = 'None'
                    neighbors = 'None'
                    # print(' - он никого не видит')
            elif reg_num in neighbors:
                # print(' - есть у ', host)
                his_neighbors.append(host)

        if len(chunked_list) > 0 and len(his_neighbors) > 0:
            # print(' - он видит: ', chunked_list)
            # print(' - его видят: ', his_neighbors)
            return chunked_list, his_neighbors
        elif len(chunked_list) == 0 and len(his_neighbors) > 0:
            # print(' - он видит: ', 0)
            # print(' - его видят: ', his_neighbors)
            return 0, his_neighbors
        elif len(chunked_list) > 0 and len(his_neighbors) == 0:
            # print(' - он видит: ', chunked_list)
            # print(' - его видят: ', 0)
            return chunked_list, 0
        elif len(chunked_list) == 0 and len(his_neighbors) == 0:
            # print(' - он видит: ', 0)
            # print(' - его видят: ', 0)
            return 0, 0
        else:
            print(' - НЕТ УСЛОВИЯ!')
            return None


# commands:
@bot.message_handler(commands=['scan'])
def scanner(message):
    def function_scanner():
        print(' - scanner start')
        date_start = datetime.now()
        # print(date_start)
        if thisFile == config.this_is_server:
            scan_neighbors = subprocess.run(['python3', '/root/bot/neighbors.py'], stdout=subprocess.PIPE)
        if thisFile == config.this_is_docker:
            scan_neighbors = subprocess.run(['python3', '/bot_ra/neighbors.py'], stdout=subprocess.PIPE)
        else:
            scan_neighbors = subprocess.run(['sudo', 'neighbors.py', config.nmap_py], stdout=subprocess.PIPE)
        result_scan_neighbors = scan_neighbors.stdout.decode('utf-8')
        fopen = open(config.file_neighbors_txt, mode='w', encoding='utf8')
        fopen.write(result_scan_neighbors)
        fopen.close()
        print(' - scan_neighbors stop, file write')
        date_end = datetime.now()
        time_itog = date_end - date_start
        bot.send_message(message.chat.id, f'отсканил, за {time_itog}.')

    threadname = f'scanner manual | {message.chat.username}'
    thread_upload = ThreadWithResult(target=function_scanner, name=threadname, args=[])
    thread_upload.start()
    thread_upload.join()

@bot.message_handler(commands=['work'])
def hubex(message):
    threadname = f'hubex | {message.chat.username}'
    threading.Thread(target=hubex_parser_auto, name=threadname, args=[message]).start()
    # thread_upload.join()

@bot.message_handler(commands=['hubex'])
def hubex_manual(message):
    threadname = f'hubex | {message.chat.username}'
    hubex_thread = threading.Thread(target=hubex_parser_manual, name=threadname, args=[message])
    hubex_thread.start()
    hubex_thread.join()

# все онлайн
@bot.message_handler(commands=['all'])
def all(message):
    date_modif_file = f"update: {dt.fromtimestamp(getctime(config.file_neighbors_txt)).strftime('%H:%M %d-%m-%Y')}"
    all_text = open(config.file_neighbors_txt, "r+", encoding='utf8').readlines()
    all_host = []
    all_none = []
    all_unknown = []

    for line in all_text:
        all_result_line = line.split()
        tachka = all_result_line[0:3]

        if 'None' in line:
            host = tachka[0] + ' ' + tachka[1] + ' ' + tachka[2]
            all_none.append(host)
        elif 'None' not in line:
            host = tachka[0] + ' ' + tachka[1] + ' ' + tachka[2]
            all_host.append(host)

    for line in all_text:
        all_result_line = line.split()
        neig = all_result_line[3:]

        neig1 = neig[0:3]
        neig2 = neig[4:7]
        neig3 = neig[8:11]
        neig4 = neig[12:15]
        neig5 = neig[16:19]

        if 'unknown' in line:
            if 'unknown' in neig1:
                host = neig1[0] + ' ' + neig1[1] + ' ' + neig1[2]
                if host not in all_unknown:
                    all_unknown.append(host)
                else: pass
            elif 'unknown' in neig2:
                host = neig2[0] + ' ' + neig2[1] + ' ' + neig2[2]
                if host not in all_unknown:
                    all_unknown.append(host)
                else:pass
            elif 'unknown' in neig3:
                host = neig3[0] + ' ' + neig3[1] + ' ' + neig3[2]
                if host not in all_unknown:
                    all_unknown.append(host)
                else:pass
            elif 'unknown' in neig4:
                host = neig4[0] + ' ' + neig4[1] + ' ' + neig4[2]
                if host not in all_unknown:
                    all_unknown.append(host)
                else:pass
            elif 'unknown' in neig5:
                host = neig5[0] + ' ' + neig5[1] + ' ' + neig5[2]
                if host not in all_unknown:
                    all_unknown.append(host)
                else:pass

    hosts_all_tg = '\n'.join(all_host)
    none_all_tg = '\n'.join(all_none)
    unknown_all_tg = '\n'.join(all_unknown)
    tg_all_tachek = len(all_host) + len(all_none) + len(all_unknown)

    splitted_text = util.split_string(hosts_all_tg, 3000)

    for text in splitted_text:
        bot.send_message(message.chat.id, text)

    bot.send_message(message.chat.id, f'{none_all_tg}\n\n{unknown_all_tg}')
    bot.send_message(message.chat.id, f"all: {tg_all_tachek}\nok: {len(all_host)}\nnone: {len(all_none)}\nunknown: {len(all_unknown)}\n{date_modif_file}")

# help
@bot.message_handler(commands=['help'])
def help(message):
    bot.send_message(message.chat.id, "список задач бота - /list\n"
                                      "отсканировать сеть (разово) - /scan\n"
                                      "все онлайн - /all\n"
                                      "выгрузить тикеты (разово) - /hubex\n"
                                      "запустить парсер Hubex - /work\n"
                                      "добавить в БД - /add 10.200_ip REG_NUM DEV_ID\n"
                                      "удалить из БД - /del 10.200_ip REG_NUM DEV_ID\n"
                                      "отменить следить - /stop то_что_в_запросе\n"
                                      "пинг - /p 192.168.0.140\n"
                                      "генератор паролей - /pass\n")

# password generator
@bot.message_handler(commands=['pass'])
def passwords(message):
    if message.from_user.username in config.users or config.admins:
        print('in: ', message.text)
        chars = '+-/*!&$#?=@<>abcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
        number = 10
        length = 16
        result = []
        for n in range(number):
            password = ''
            for i in range(length):
                password += random.choice(chars)
            result.append(password)
        result = '\n'.join(result)
        print(result)
        bot.send_message(message.chat.id, result)
    else:
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')

@bot.message_handler(commands=['f'])
def find(message):
    if message.from_user.username in config.users or config.admins:
        input = message.text.split()
        find_word = input[1]
        print('user: ', message.from_user.username, ', ищет: ', find_word)
        with open('140.txt', 'r', encoding='utf8') as fopen198:
            fread198 = fopen198.readlines()
            for line in fread198:
                if find_word in line:
                    result_tg = ''.join(line)
                    bot.send_message(message.chat.id, result_tg)

        def open200():
            result = []
            with open('200.txt', 'r', encoding='utf8') as fopen200:
                fread200 = fopen200.readlines()
                for stroka in fread200:
                    if find_word in stroka:
                        result.append(stroka)
                return result

        op200 = open200()
        if op200 == []:
            pass
        else:
            for line in op200:
                result_tg = str(line)
                bot.send_message(message.chat.id, result_tg)

    else:
        print(f'у {message.from_user.username} нет доступа')
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')

@bot.message_handler(commands=['scan_200'])
def scan200(message):
    if message.from_user.username in config.users or config.admins:
        threading.Thread(target=scan_200, name='scan_200', args=[]).start()
    else:
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')

@bot.message_handler(commands=['stop'])
def stop(message):
    if message.from_user.username in config.users or config.admins:
        save = message.text
        result = save.split()
        var = result[1]
        print('var: ', var)
        with open(config.file_neighbors_txt, 'a', encoding='utf8') as update:
            update.write(var + ' удален из_мониторинга\n')
            update.close()
    else:
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')

@bot.message_handler(commands=['add'])
def add_data_200(message):
    if message.from_user.username in config.users or config.admins:
        try:
            var = message.text.split()
            print('command: ', var)
            result = var[1] + ' ' + var[2] + ' ' + var[3]
            with open(config.file_200_txt, 'a', encoding='utf8') as update:
                update.write(result + '\n')
                update.close()
            bot.send_message(message.chat.id, f'{result} - записан.')
        except IndexError:
            bot.send_message(message.chat.id,
                             f'{message.from_user.username}, тут три значения, IPпробелREG_NUMпробелDEV_ID!')
    else:
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')

@bot.message_handler(commands=['del'])
def delete_data_200(message):
    if message.from_user.username in config.users or config.admins:
        var = message.text.split()
        print('command: ', var)
        result = var[1] + ' ' + var[2] + ' ' + var[3]
        print('result: ', result)
        with open(config.file_200_txt, 'r') as f:
            old_data = f.read()
        new_data = old_data.replace(result, '')
        with open(config.file_200_txt, 'w') as f:
            f.write(new_data)
        bot.send_message(message.chat.id, f'{result} - удален.')
    else:
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')

@bot.message_handler(commands=['p'])
def ping(message):
    if message.from_user.username in config.admins or config.users:
        print('user: ', message.from_user.username, ' command ping: ', message.text)
        result_input = message.text
        result = result_input.split()
        ip = str(result[1])
        reg_num = None
        threadname = f'ping {ip} | {message.from_user.username}'
        thread = ThreadWithResult(target=ping_function, name=threadname, args=[message, ip])
        thread.start()
        thread.join()
        result_output = thread.result
        print('result_output: ', result_output)

        if result_output == 0:
            print('ok!')
            result_tg = f'ping {ip} ok!'
            function_mqtt = str('function_mqtt_about_system ' + ip + ' ' + 'None')
            keyboard = types.InlineKeyboardMarkup()
            callback_button3 = types.InlineKeyboardButton(text="закрыть", callback_data='close')
            callback_button4 = types.InlineKeyboardButton(text="mqtt:1883", callback_data=function_mqtt)
            keyboard.add(callback_button3, callback_button4)
            bot.send_message(message.chat.id, result_tg, reply_markup=keyboard)


        else:
            print('don`t ok ...')
            result_tg = f'ping {ip} dont`t ok ...'
            function_ping = str('function_ping ' + ip + ' ' + 'None')
            ping_while_return_false = str('ping_while_return_false ' + ip + ' ' + 'None')
            keyboard = types.InlineKeyboardMarkup()
            callback_button = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
            callback_button2 = types.InlineKeyboardButton(text="отложить", callback_data='sleep')
            callback_button3 = types.InlineKeyboardButton(text="закрыть", callback_data='close')
            callback_button4 = types.InlineKeyboardButton(text="пинговать", callback_data=ping_while_return_false)
            keyboard.add(callback_button, callback_button2, callback_button3, callback_button4)
            bot.send_message(message.chat.id, result_tg, reply_markup=keyboard)
    else:
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')

@bot.message_handler(commands=['list'])
def handle_text(message):
    if message.from_user.username in config.users or config.admins:
        # threading.enumerate().name = 'None'
        for i in range(threading.active_count()):
            # print(threading.enumerate()[i])
            # print(threading.enumerate()[i].name)
            bot.send_message(message.chat.id, f'{threading.enumerate()[i].name}')
    else:
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')

# lalala
@bot.message_handler(content_types=['text'])
def lalala(message):
    find_word = str(message.text)
    if message.from_user.username in config.users or config.admins:
        print('user:', message.from_user.username, ', ищет:', find_word)
        if find_word == 'test':
            print('выполнилась функция test, ', message.from_user.username, ', find_word:', find_word)
            input_tg = message.text
            bot.send_message(chat_id=message.chat.id, text='тест, тест, и чо?')
            bot.send_sticker(message.chat.id, sticker="CAACAgIAAxkBAAIF3WLzouU6ZSFqiwWr9XckkUJDkDqxAAJQAANSiZEj0YLxZBXhJNgpBA")
        elif find_word:
            with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
                data = file.readlines()
                soseds = []

                for line in data:
                    all_result_line = line.split()
                    tachka = all_result_line[0:3]
                    neig = all_result_line[3:]

                    neig1 = neig[0:4]
                    neig2 = neig[4:8]
                    neig3 = neig[8:12]
                    neig4 = neig[12:16]
                    neig5 = neig[16:20]

                    if find_word in str(tachka):
                        result_ip = tachka[0]
                        reg_num = tachka[1]
                        dev_id = tachka[2]

                        print(find_word, 'in tachka: ', tachka)

                        function_ping = str('function_ping ' + result_ip + ' ' + reg_num)
                        sleep = str('sleep ' + result_ip + ' ' + reg_num)
                        function_mqtt_about_system = str('function_mqtt_about_system ' + result_ip + ' ' + reg_num)
                        function_mqtt_about_sensors = str('function_mqtt_about_sensors ' + result_ip + ' ' + reg_num)
                        tag_storage = str('tag_storage ' + result_ip + ' ' + reg_num + ' ' + dev_id)
                        function_broadcast_config_create = str('broad_create ' + result_ip + ' ' + reg_num)

                        keyboard = types.InlineKeyboardMarkup()
                        callback_button_about_system = types.InlineKeyboardButton(text="о системе", callback_data=function_mqtt_about_system)
                        callback_button_about_sensors = types.InlineKeyboardButton(text="об оборудовании", callback_data=function_mqtt_about_sensors)
                        callback_button_tag_storage = types.InlineKeyboardButton(text="о справочниках", callback_data=tag_storage)
                        callback_button_broadcast_config_create = types.InlineKeyboardButton(text="бродкасты", callback_data=function_broadcast_config_create)
                        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

                        keyboard.add(callback_button_about_system, callback_button_about_sensors)
                        keyboard.add(callback_button_broadcast_config_create, callback_button_tag_storage)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)

                        result_tg = str('<b>' + result_ip + ' ' + reg_num + ' ' + dev_id + '</b>')
                        bot.send_message(message.chat.id, result_tg, reply_markup=keyboard, parse_mode='html')


                    elif find_word in str(neig):
                        # print(' - neig: ', neig)
                        if find_word in str(neig1):
                            print(tachka + neig1)
                            soseds.append(tachka + neig1)
                        elif find_word in str(neig2):
                            print(tachka + neig2)
                            soseds.append(tachka + neig2)
                        elif find_word in str(neig3):
                            print(tachka + neig3)
                            soseds.append(tachka + neig3)
                        elif find_word in str(neig4):
                            print(tachka + neig4)
                            soseds.append(tachka + neig4)
                        elif find_word in str(neig5):
                            print(tachka + neig5)
                            soseds.append(tachka + neig5)

                if soseds == []:
                    pass
                else:
                    print(' - soseds: ', soseds)
                    host = str(soseds[0][3])
                    reg_num = str(soseds[0][4])
                    dev_id = str(soseds[0][5])

                    print('кол-во соседей: ', len(soseds))

                    if host == 'unknown':
                        print('--- !unknown host! ', reg_num, 'ищу бродкасты')

                        bot.send_message(chat_id=message.chat.id, text=f'{host} {reg_num} {dev_id}\n - ожидайте ...')

                        def function_broadcast_config_create():
                            spreadsheet_id = config.broadcast_spreadsheet_id
                            major = 'ROWS'
                            range_belgorod = 'Белгород!A2:D255'  # 'Sheet2!A2:E10'
                            sheet_broadcats_belgorog = google_sheets_read(spreadsheet_id, range_belgorod, major)
                            range_kursk = 'Курск!A2:D255'
                            sheet_broadcats_kursk = google_sheets_read(spreadsheet_id, range_kursk, major)
                            range_tambov = 'Тамбов!A2:D255'
                            sheet_broadcats_tambov = google_sheets_read(spreadsheet_id, range_tambov, major)
                            range_orel = 'Орел!A2:D255'
                            sheet_broadcats_orel = google_sheets_read(spreadsheet_id, range_orel, major)
                            range_primorie = 'Приморье!A2:D255'
                            sheet_broadcats_primorie = google_sheets_read(spreadsheet_id, range_primorie, major)
                            for row in sheet_broadcats_belgorog:
                                if reg_num in row:
                                    reg_num_from_sheet = row[0]
                                    broadcast_ip_from_sheet = row[1]
                                    mikrotik_ip = row[2]
                                    return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                            for row in sheet_broadcats_kursk:
                                if reg_num in row:
                                    reg_num_from_sheet = row[0]
                                    broadcast_ip_from_sheet = row[1]
                                    mikrotik_ip = row[2]
                                    return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                            for row in sheet_broadcats_tambov:
                                if reg_num in row:
                                    reg_num_from_sheet = row[0]
                                    broadcast_ip_from_sheet = row[1]
                                    mikrotik_ip = row[2]
                                    return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                            for row in sheet_broadcats_orel:
                                if reg_num in row:
                                    reg_num_from_sheet = row[0]
                                    broadcast_ip_from_sheet = row[1]
                                    mikrotik_ip = row[2]
                                    return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                            for row in sheet_broadcats_primorie:
                                if reg_num in row:
                                    reg_num_from_sheet = row[0]
                                    broadcast_ip_from_sheet = row[1]
                                    mikrotik_ip = row[2]
                                    return reg_num_from_sheet + ' ' + broadcast_ip_from_sheet + ' ' + mikrotik_ip

                        broadcasts_from_table = None
                        broadcasts_from_table = function_broadcast_config_create()
                        date_modif_file = f"обновлено: {dt.fromtimestamp(getctime(config.file_neighbors_txt)).strftime('%H:%M %d-%m-%Y')}"

                        if broadcasts_from_table != None:
                            result = broadcasts_from_table.split()
                            reg_num_from_sheet = result[0]
                            broadcast_ip = result[1]
                            mikrotik_ip = result[2]
                            print(' - broadcasts_from_table: ', broadcasts_from_table)

                            if len(soseds) == 1:
                                print(' - выполнилось условие = 1')

                                sosed0 = soseds[0][6] + ' | ' + soseds[0][0] + ' ' + soseds[0][1] + ' ' + soseds[0][2]
                                result_tg = f'{host} {reg_num} {dev_id}\n\n{sosed0}\n{date_modif_file}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip}\n\nssh root@{broadcast_ip}\ntelnet {mikrotik_ip}'

                                name_button_info = f'о связи через {soseds[0][0]}'
                                info_neighbor_get = f'i_mqtt_heig {soseds[0][0]} {soseds[0][1]} {broadcast_ip}'

                                if message.from_user.username in config.admins:
                                    keyboard = types.InlineKeyboardMarkup()
                                    callback_button_info_neighbor = types.InlineKeyboardButton(text=name_button_info, callback_data=info_neighbor_get)
                                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                                    keyboard.add(callback_button_info_neighbor)
                                    keyboard.add(callback_button_close)
                                    bot.send_message(chat_id=message.chat.id, text=result_tg, reply_markup=keyboard)
                                else:
                                    bot.send_message(chat_id=message.chat.id, text=result_tg)


                            elif len(soseds) == 2:
                                print(' - выполнилось условие = 2')

                                sosed0 = soseds[0][6] + ' | ' + soseds[0][0] + ' ' + soseds[0][1] + ' ' + soseds[0][2]
                                sosed1 = soseds[1][6] + ' | ' + soseds[1][0] + ' ' + soseds[1][1] + ' ' + soseds[1][2]
                                result_tg = f'{host} {reg_num} {dev_id}\n\n{sosed0}\n{sosed1}\n{date_modif_file}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip}\n\nssh root@{broadcast_ip}\ntelnet {mikrotik_ip}'

                                name_button_info0 = f'о симках через {soseds[0][0]}'
                                name_button_info1 = f'о симках через {soseds[1][0]}'

                                info_neighbor_get0 = f'i_mqtt_heig {soseds[0][0]} {soseds[0][1]} {broadcast_ip}'
                                info_neighbor_get1 = f'i_mqtt_heig {soseds[1][0]} {soseds[1][1]} {broadcast_ip}'

                                if message.from_user.username in config.admins:
                                    keyboard = types.InlineKeyboardMarkup()
                                    callback_button_info_neighbor0 = types.InlineKeyboardButton(text=name_button_info0, callback_data=info_neighbor_get0)
                                    callback_button_info_neighbor1 = types.InlineKeyboardButton(text=name_button_info1, callback_data=info_neighbor_get1)
                                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                                    keyboard.add(callback_button_info_neighbor0)
                                    keyboard.add(callback_button_info_neighbor1)
                                    keyboard.add(callback_button_close)
                                    bot.send_message(chat_id=message.chat.id, text=result_tg, reply_markup=keyboard)
                                else:
                                    bot.send_message(chat_id=message.chat.id, text=result_tg)


                            elif len(soseds) == 3:
                                print(' - выполнилось условие = 3')

                                sosed0 = soseds[0][6] + ' | ' + soseds[0][0] + ' ' + soseds[0][1] + ' ' + soseds[0][2]
                                sosed1 = soseds[1][6] + ' | ' + soseds[1][0] + ' ' + soseds[1][1] + ' ' + soseds[1][2]
                                sosed2 = soseds[2][6] + ' | ' + soseds[2][0] + ' ' + soseds[2][1] + ' ' + soseds[2][2]
                                result_tg = f'{host} {reg_num} {dev_id}\n\n{sosed0}\n{sosed1}\n{sosed2}\n{date_modif_file}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip}\n\nssh root@{broadcast_ip}\ntelnet {mikrotik_ip}'

                                name_button_info0 = f'о симках через {soseds[0][0]}'
                                name_button_info1 = f'о симках через {soseds[1][0]}'
                                name_button_info2 = f'о симках через {soseds[2][0]}'

                                info_neighbor_get0 = f'i_mqtt_heig {soseds[0][0]} {soseds[0][1]} {broadcast_ip}'
                                info_neighbor_get1 = f'i_mqtt_heig {soseds[1][0]} {soseds[1][1]} {broadcast_ip}'
                                info_neighbor_get2 = f'i_mqtt_heig {soseds[2][0]} {soseds[2][1]} {broadcast_ip}'

                                if message.from_user.username in config.admins:
                                    keyboard = types.InlineKeyboardMarkup()
                                    callback_button_info_neighbor0 = types.InlineKeyboardButton(text=name_button_info0,
                                                                                                callback_data=info_neighbor_get0)
                                    callback_button_info_neighbor1 = types.InlineKeyboardButton(text=name_button_info1,
                                                                                                callback_data=info_neighbor_get1)
                                    callback_button_info_neighbor2 = types.InlineKeyboardButton(text=name_button_info2,
                                                                                                callback_data=info_neighbor_get2)
                                    callback_button_close = types.InlineKeyboardButton(text="закрыть",
                                                                                       callback_data='close')
                                    keyboard.add(callback_button_info_neighbor0)
                                    keyboard.add(callback_button_info_neighbor1)
                                    keyboard.add(callback_button_info_neighbor2)
                                    keyboard.add(callback_button_close)
                                    bot.send_message(chat_id=message.chat.id, text=result_tg, reply_markup=keyboard)
                                else:
                                    bot.send_message(chat_id=message.chat.id, text=result_tg)


                            elif len(soseds) == 4:
                                print(' - выполнилось условие = 4')

                                sosed0 = soseds[0][6] + ' | ' + soseds[0][0] + ' ' + soseds[0][1] + ' ' + soseds[0][2]
                                sosed1 = soseds[1][6] + ' | ' + soseds[1][0] + ' ' + soseds[1][1] + ' ' + soseds[1][2]
                                sosed2 = soseds[2][6] + ' | ' + soseds[2][0] + ' ' + soseds[2][1] + ' ' + soseds[2][2]
                                sosed3 = soseds[3][6] + ' | ' + soseds[3][0] + ' ' + soseds[3][1] + ' ' + soseds[3][2]
                                result_tg = f'{host} {reg_num} {dev_id}\n\n{sosed0}\n{sosed1}\n{sosed2}\n{sosed3}\n{date_modif_file}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip}\n\nssh root@{broadcast_ip}\ntelnet {mikrotik_ip}'

                                name_button_info0 = f'о симках через {soseds[0][0]}'
                                name_button_info1 = f'о симках через {soseds[1][0]}'
                                name_button_info2 = f'о симках через {soseds[2][0]}'
                                name_button_info3 = f'о симках через {soseds[3][0]}'

                                info_neighbor_get0 = f'i_mqtt_heig {soseds[0][0]} {soseds[0][1]} {broadcast_ip}'
                                info_neighbor_get1 = f'i_mqtt_heig {soseds[1][0]} {soseds[1][1]} {broadcast_ip}'
                                info_neighbor_get2 = f'i_mqtt_heig {soseds[2][0]} {soseds[2][1]} {broadcast_ip}'
                                info_neighbor_get3 = f'i_mqtt_heig {soseds[3][0]} {soseds[3][1]} {broadcast_ip}'

                                if message.from_user.username in config.admins:
                                    keyboard = types.InlineKeyboardMarkup()
                                    callback_button_info_neighbor0 = types.InlineKeyboardButton(text=name_button_info0,
                                                                                                callback_data=info_neighbor_get0)
                                    callback_button_info_neighbor1 = types.InlineKeyboardButton(text=name_button_info1,
                                                                                                callback_data=info_neighbor_get1)
                                    callback_button_info_neighbor2 = types.InlineKeyboardButton(text=name_button_info2,
                                                                                                callback_data=info_neighbor_get2)
                                    callback_button_info_neighbor3 = types.InlineKeyboardButton(text=name_button_info3,
                                                                                                callback_data=info_neighbor_get3)
                                    callback_button_close = types.InlineKeyboardButton(text="закрыть",
                                                                                       callback_data='close')
                                    keyboard.add(callback_button_info_neighbor0)
                                    keyboard.add(callback_button_info_neighbor1)
                                    keyboard.add(callback_button_info_neighbor2)
                                    keyboard.add(callback_button_info_neighbor3)
                                    keyboard.add(callback_button_close)
                                    bot.send_message(chat_id=message.chat.id, text=result_tg, reply_markup=keyboard)
                                else:
                                    bot.send_message(chat_id=message.chat.id, text=result_tg)


                            elif len(soseds) >= 5:
                                print(' - выполнилось условие >= 5')
                                sosed0 = soseds[0][6] + ' | ' + soseds[0][0] + ' ' + soseds[0][1] + ' ' + soseds[0][2]
                                sosed1 = soseds[1][6] + ' | ' + soseds[1][0] + ' ' + soseds[1][1] + ' ' + soseds[1][2]
                                sosed2 = soseds[2][6] + ' | ' + soseds[2][0] + ' ' + soseds[2][1] + ' ' + soseds[2][2]
                                sosed3 = soseds[3][6] + ' | ' + soseds[3][0] + ' ' + soseds[3][1] + ' ' + soseds[3][2]
                                sosed4 = soseds[4][6] + ' | ' + soseds[4][0] + ' ' + soseds[4][1] + ' ' + soseds[4][2]
                                result_tg = f'{host} {reg_num} {dev_id}\n\n{sosed0}\n{sosed1}\n{sosed2}\n{sosed3}\n{sosed4}\n{date_modif_file}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip}\n\nssh root@{broadcast_ip}\ntelnet {mikrotik_ip}'

                                name_button_info0 = f'о симках через {soseds[0][0]}'
                                name_button_info1 = f'о симках через {soseds[1][0]}'
                                name_button_info2 = f'о симках через {soseds[2][0]}'
                                name_button_info3 = f'о симках через {soseds[3][0]}'
                                name_button_info4 = f'о симках через {soseds[4][0]}'

                                info_neighbor_get0 = f'i_mqtt_heig {soseds[0][0]} {soseds[0][1]} {broadcast_ip}'
                                info_neighbor_get1 = f'i_mqtt_heig {soseds[1][0]} {soseds[1][1]} {broadcast_ip}'
                                info_neighbor_get2 = f'i_mqtt_heig {soseds[2][0]} {soseds[2][1]} {broadcast_ip}'
                                info_neighbor_get3 = f'i_mqtt_heig {soseds[3][0]} {soseds[3][1]} {broadcast_ip}'
                                info_neighbor_get4 = f'i_mqtt_heig {soseds[4][0]} {soseds[4][1]} {broadcast_ip}'

                                if message.from_user.username in config.admins:
                                    keyboard = types.InlineKeyboardMarkup()
                                    callback_button_info_neighbor0 = types.InlineKeyboardButton(text=name_button_info0,
                                                                                                callback_data=info_neighbor_get0)
                                    callback_button_info_neighbor1 = types.InlineKeyboardButton(text=name_button_info1,
                                                                                                callback_data=info_neighbor_get1)
                                    callback_button_info_neighbor2 = types.InlineKeyboardButton(text=name_button_info2,
                                                                                                callback_data=info_neighbor_get2)
                                    callback_button_info_neighbor3 = types.InlineKeyboardButton(text=name_button_info3,
                                                                                                callback_data=info_neighbor_get3)
                                    callback_button_info_neighbor4 = types.InlineKeyboardButton(text=name_button_info4,
                                                                                                callback_data=info_neighbor_get4)
                                    callback_button_close = types.InlineKeyboardButton(text="закрыть",
                                                                                       callback_data='close')
                                    keyboard.add(callback_button_info_neighbor0)
                                    keyboard.add(callback_button_info_neighbor1)
                                    keyboard.add(callback_button_info_neighbor2)
                                    keyboard.add(callback_button_info_neighbor3)
                                    keyboard.add(callback_button_info_neighbor4)
                                    keyboard.add(callback_button_close)
                                    bot.send_message(chat_id=message.chat.id, text=result_tg, reply_markup=keyboard)
                                else:
                                    bot.send_message(chat_id=message.chat.id, text=result_tg)


                            else:
                                print('- нету условия при росписи соседей и бродкастов')
                        else:
                            print('\nеще иначе\n')

            def open200():
                result = []
                with open(config.file_200_txt, 'r', encoding='utf8') as fopen200:
                    fread200 = fopen200.readlines()
                    for stroka in fread200:
                        if find_word in stroka:
                            # print('нашел строку: ', stroka)
                            result.append(stroka)
                    return result

            op200 = open200()

            if op200 == []:
                input = find_word
                text_button = f'следить за {input}'
                function_watch = str('function_watch ' + input)
                result_output = f'{input} - не найдено.'
                keyboard4 = types.InlineKeyboardMarkup()
                callback_button_watch = types.InlineKeyboardButton(text=text_button, callback_data=function_watch)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                keyboard4.add(callback_button_watch, callback_button_close)
                bot.send_message(message.chat.id, result_output, reply_markup=keyboard4)

            else:
                for line in op200:
                    result_output = line.split()
                    result_tg = str(line)
                    ip = result_output[0]
                    reg_num = result_output[1]
                    dev_id = result_output[2]
                    function_ping = str('function_ping ' + ip + ' ' + reg_num)
                    function_watch = str('function_watch ' + find_word)
                    print(result_output)
                    sleep = str('sleep ' + ip + ' ' + reg_num)
                    tag_storage = str('tag_storage ' + ip + ' ' + reg_num + ' ' + dev_id)

                    keyboard = types.InlineKeyboardMarkup()
                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                    callback_button_tag_storage = types.InlineKeyboardButton(text="о справочниках", callback_data=tag_storage)
                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                    callback_button_watch = types.InlineKeyboardButton(text="следить", callback_data=function_watch)
                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

                    if message.from_user.username in config.users:
                        keyboard.add(callback_button_ping, callback_button_tag_storage)
                        keyboard.add(callback_button_watch, callback_button_sleep, callback_button_close)
                        bot.send_message(message.chat.id, result_tg, reply_markup=keyboard)
                    elif message.from_user.username in config.admins:
                        keyboard.add(callback_button_ping, callback_button_tag_storage)
                        keyboard.add(callback_button_watch, callback_button_sleep, callback_button_close)
                        bot.send_message(message.chat.id, result_tg, reply_markup=keyboard)

    else:
        print(f'у {message.from_user.username} нет доступа')
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')


# кнопочки
@bot.callback_query_handler(func=lambda call: True)
def callback_inline(call):
    print(' - юзер ', call.message.chat.username, ' нажал кнопку ', call.data)

    if call.data == 'test':
        print(call.data)
        print(call.callback_data)

    # закрыть кнопки
    elif 'close' in call.data:
        input = call.message.text
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{input}')

    # пинг - кнопка
    elif 'function_ping' in call.data:
        result = call.data.split()
        command = result[0]
        result_ip = result[1]
        reg_num = 'None'
        reg_num = result[2]
        input = call.message.text

        ping = ping_function(input, result_ip)

        print()
        print('command: ', command)
        print('ip: ', result_ip)
        print('reg_num: ', reg_num)
        print('-', ping)
        print()

        if ping == 0:
            function_ping = str('function_ping ' + result_ip + ' ' + reg_num)
            sleep = str('sleep ' + result_ip + ' ' + reg_num)
            function_mqtt_about_system = str('function_mqtt_about_system ' + result_ip + ' ' + reg_num)
            function_mqtt_about_sensors = str('function_mqtt_about_sensors ' + result_ip + ' ' + reg_num)

            keyboard = types.InlineKeyboardMarkup()
            callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
            callback_button_about_system = types.InlineKeyboardButton(text="о системе", callback_data=function_mqtt_about_system)
            callback_button_about_sensors = types.InlineKeyboardButton(text="об оборудовании", callback_data=function_mqtt_about_sensors)
            callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
            callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

            if call.message.chat.username in config.users:
                keyboard.add(callback_button_about_system, callback_button_about_sensors)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{input}\n - ping {result_ip} ok!', reply_markup=keyboard)
            elif call.message.chat.username in config.admins:
                keyboard.add(callback_button_about_system, callback_button_about_sensors)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{input}\n - ping {result_ip} ok!', reply_markup=keyboard)
            else:
                bot.send_message(call.message.chat.id, f'у {call.message.chat.username} нет доступа')

        elif ping != 0:
            function_ping = str('function_ping ' + result_ip + ' ' + reg_num)
            function_watch = str('function_watch ' + reg_num)
            ping_while_return_false = str('ping_while_return_false ' + result_ip + ' ' + reg_num)
            sleep = str('sleep ' + result_ip + ' ' + reg_num)

            keyboard = types.InlineKeyboardMarkup()
            callback_button = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
            callback_button4 = types.InlineKeyboardButton(text="пинговать", callback_data=ping_while_return_false)
            callback_button2 = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
            callback_button3 = types.InlineKeyboardButton(text="следить", callback_data=function_watch)
            callback_button6 = types.InlineKeyboardButton(text="закрыть", callback_data='close')

            if call.message.chat.username in config.users:
                keyboard.add(callback_button, callback_button2, callback_button3, callback_button4, callback_button6)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{input}\n - ping {result_ip} don`t ok ...', reply_markup=keyboard)
            elif call.message.chat.username in config.admins:
                keyboard.add(callback_button, callback_button2, callback_button3, callback_button4, callback_button6)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{input}\n - ping {result_ip} don`t ok ...', reply_markup=keyboard)
            else:
                bot.send_message(call.message.chat.id, f'у {call.message.chat.username} нет доступа')

        else:
            print('pdc =(')

    # отложить
    elif 'sleep' in call.data:
        data = call.data.split()
        print('data: ', data)
        input = call.message.text
        result = input.split()
        print(result)
        reg_num = result[1]
        result_ip = data[1]
        reg_num = data[2]
        function_ping = str('function_ping ' + result_ip + ' ' + reg_num)
        sleep = str('sleep ' + result_ip + ' ' + reg_num)

        def sleep_ping_function():
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{input}\n - отложено на {config.time_sleep} сек')
            time.sleep(config.time_sleep)
            keyboard = types.InlineKeyboardMarkup()
            callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
            callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
            callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.send_message(chat_id=call.message.chat.id, text=input, reply_markup=keyboard)

        name_thread = reg_num or result[1]
        name_thread = name_thread[1]
        name_thread = f'sleep {name_thread} | {call.message.chat.username}'
        threading.Thread(target=sleep_ping_function, name=name_thread, args=[]).start()

    # следить - кнопка
    elif 'function_watch' in call.data:
        input = call.data.split()
        print(input)
        var = input[1]

        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{call.message.text}\n{var} - слежу.')

        def watch_function():
            sys.setrecursionlimit(config.time_setrecursionlimit)
            try:
                fopen = open(config.file_neighbors_txt, mode='r+', encoding='utf8')
                fread = fopen.readlines()
                fopen.close()

                for lines in fread:
                    line = lines.split()
                    line = line[0:3]
                    line2 = str(line)

                    if var in line2:
                        print('line: ', line)
                        result = line
                        print('result: ', result)
                        print(type(result))
                        result_ip = result[0]
                        print(result_ip)
                        reg_num = result[1]
                        dev_id = result[2]

                        function_ping = str('function_ping ' + result_ip + ' ' + reg_num)
                        sleep = str('sleep ' + result_ip + ' ' + reg_num)
                        message_tg = f'{call.message.text}\n - отслежено:\n{result_ip} {reg_num} {dev_id}'
                        print('message_tg: ', message_tg)

                        keyboard = types.InlineKeyboardMarkup()

                        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

                        if call.message.chat.username in config.users:
                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                            bot.send_message(chat_id=call.message.chat.id, text=message_tg, reply_markup=keyboard)
                        elif call.message.chat.username in config.admins:
                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                            bot.send_message(chat_id=call.message.chat.id, text=message_tg, reply_markup=keyboard)
                        else:
                            bot.send_message(call.message.chat.id, f'у {call.message.from_user.username} нет доступа')
                        break
                else:
                    time.sleep(config.time_watch)
                    # time.sleep(1)
                    print('restart watch', var)
                    watch_function()
            except RecursionError:
                print(f' - конец наблюдению за {var} | {call.from_user.username}')

        namethread = f'watch {var} | {call.from_user.username}'
        threading.Thread(target=watch_function, name=namethread, args=[]).start()

    # если не найдено - ни где
    elif 'find_no_base' in call.data:

        print('call.data: ', call.data)
        result_input = call.data.split()

        var = str(result_input[1])
        print(result_input)

        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{var} - слежу.')

        def watch_function():
            sys.setrecursionlimit(config.time_setrecursionlimit)
            # fopen = open('140.txt', mode='r+', encoding='utf8')
            fopen = open(config.file_neighbors_txt, mode='r+', encoding='utf8')
            fread = fopen.readlines()
            fopen.close()

            for lines in fread:
                line = lines.split()
                line = line[0:3]
                line2 = str(line)

                if var in line2:
                    print('line: ', line)
                    result = line
                    print('result: ', result)
                    print(type(result))
                    result_ip = result[0]
                    print(result_ip)
                    reg_num = result[1]
                    dev_id = result[2]

                    function_ping = str('function_ping ' + result_ip + ' ' + reg_num)
                    function_mqtt_about_system = str('function_mqtt_about_system ' + result_ip + ' ' + reg_num)
                    function_mqtt_about_sensors = str('function_mqtt_about_sensors ' + result_ip + ' ' + reg_num)
                    sleep = str('sleep ' + result_ip + ' ' + reg_num)

                    message_tg = f'{call.message.text}\n - отслежено:\n{result_ip} {reg_num} {dev_id}'
                    print('message_tg: ', message_tg)

                    keyboard4 = types.InlineKeyboardMarkup()
                    callback_button_about_system = types.InlineKeyboardButton(text="о системе",
                                                                              callback_data=function_mqtt_about_system)
                    callback_button_about_sensors = types.InlineKeyboardButton(text="об оборудовании",
                                                                               callback_data=function_mqtt_about_sensors)
                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

                    if call.message.chat.username in config.users:
                        keyboard4.add(callback_button_about_system, callback_button_about_sensors)
                        keyboard4.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.send_message(chat_id=call.message.chat.id, text=message_tg, reply_markup=keyboard4)
                    elif call.message.chat.username in config.admins:
                        keyboard4.add(callback_button_about_system, callback_button_about_sensors)
                        keyboard4.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.send_message(chat_id=call.message.chat.id, text=message_tg, reply_markup=keyboard4)
                    else:
                        bot.send_message(call.message.chat.id, f'у {call.message.from_user.username} нет доступа')
                    break
            else:
                time.sleep(config.time_watch)
                print('restart watch', var)
                watch_function()

        namethread = f'watch {var} | {call.message.chat.username}'
        threading.Thread(target=watch_function, name=namethread, args=[]).start()

    # о службах
    elif 'function_about_services' in call.data:
        input = call.data.split()
        device = input[1]
        reg_num = input[2]
        print('input:', input)
        # print('call.message: ', call.message.text)

        command = 'systemctl is-active --quiet "broadcast_client" && echo 1 || echo 0; systemctl is-active --quiet "broadcast_server" && echo 1 || echo 0; systemctl is-active --quiet "tagpack_server" && echo 1 || echo 0; systemctl is-active --quiet "deploy_server" && echo 1 || echo 0; systemctl is-active --quiet "wb-rules" && echo 1 || echo 0; systemctl is-active --quiet "rfid-mqtt" && echo 1 || echo 0; systemctl is-active --quiet "mqtt_agent" && echo 1 || echo 0;'

        threadname = f'about_services {device}  | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                  args=[device, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()
        result_tg = thread.result
        print('result: ', thread.result)

        broadcast_client = str(result_tg[0])
        broadcast_server = str(result_tg[1])
        tagpack_server = str(result_tg[2])
        deploy_server = str(result_tg[3])
        wb_rules = str(result_tg[4])
        rfid_mqtt = str(result_tg[5])
        mqtt_agent = str(result_tg[6])

        print(' broadcast_client: ', broadcast_client, 'broadcast_server: ', broadcast_server, 'tagpack_server: ',
              tagpack_server, 'deploy_server: ', deploy_server, 'wb_rules: ', wb_rules, 'rfid_mqtt: ', rfid_mqtt,
              'mqtt_agent: ', mqtt_agent)
        result_services = f"{call.message.text}\n\nbroadcast_client: {broadcast_client}broadcast_server: {broadcast_server}tagpack_server: {tagpack_server}deploy_server: {deploy_server}wb_rules: {wb_rules}rfid_mqtt: {rfid_mqtt}mqtt_agent: {mqtt_agent}\n"

        function_ping = str('function_ping ' + device + ' ' + reg_num)
        function_about_services = str('function_about_services ' + device + ' ' + reg_num)
        sleep = str('sleep ' + device + ' ' + reg_num)
        # function_about_mqtt = str('function_about_mqtt ' + device)
        keyboard5 = types.InlineKeyboardMarkup()
        callback_button = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button2 = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button3 = types.InlineKeyboardButton(text="службы", callback_data=function_about_services)
        callback_button6 = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        if call.message.chat.username in config.users:
            keyboard5.add(callback_button, callback_button2, callback_button6)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=result_services, reply_markup=keyboard5)
        elif call.message.chat.username in config.admins:
            keyboard5.add(callback_button, callback_button2, callback_button3, callback_button6)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=result_services, reply_markup=keyboard5)
        else:
            print(f'у {call.message.from_user.username} нет доступа')

    # пинговать, пока не будет онлайн
    elif 'ping_while_return_false' in call.data:

        input = call.data.split()
        ip = input[1]
        reg_num = input[2]
        print('пинговать ', input, '|', call.message.chat.username)
        result_output = f'{call.message.text}\n - пингую {ip}'
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=result_output)

        def ping_while_return_false():
            response = os.system("ping -c 4 " + ip)
            if response == 0:
                result_tg = f'{call.message.text}\n\n - {ip} - online!'
                function_ping = str('function_ping ' + ip + ' ' + reg_num)
                sleep = str('sleep ' + ip + ' ' + reg_num)
                keyboard5 = types.InlineKeyboardMarkup()
                callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                keyboard5.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.send_message(call.message.chat.id, result_tg, reply_markup=keyboard5)
            else:
                time.sleep(config.time_ping)
                print('restart ping ', ip)
                ping_while_return_false()

        threadname = str('ping ' + ip + ' | ' + call.message.chat.username)
        threading.Thread(target=ping_while_return_false, name=threadname, args=[]).start()

    # о системе
    elif 'function_mqtt_about_system' in call.data:
        input = call.data.split()
        ip = input[1]
        reg_num = input[2]
        broker = ip
        sleep = str('sleep ' + ip + ' ' + reg_num)
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        vehicle_reg_num_topic = '/devices/vehicle/controls/_vehicle_reg_num'
        vin_topic = '/devices/power_status/controls/Vin'
        la1_topic = '/devices/metrics/controls/load_average_1min'
        load_average_5min_topic = '/devices/metrics/controls/load_average_5min'
        load_average_15min_topic = '/devices/metrics/controls/load_average_15min'
        current_uptime_topic = '/devices/system/controls/Current uptime'
        short_sn_topic = '/devices/system/controls/Short SN'
        version_topic = '/rusagro/version'
        arm_device_topic = '/services/user_interface/time_stamp'
        vehicle_type_topic = '/devices/vehicle/controls/vehicle_type'
        vpn_ip_topic = '/devices/network_extended/controls/OVPN_1 IP'
        vpn_ip2_topic = '/devices/network_extended/controls/OVPN_2 IP'
        vpn_ip3_topic = '/devices/network_extended/controls/OVPN_3 IP'
        wifi_mac_topic = '/devices/network_extended/controls/Wi-Fi MAC'
        data_total_space_topic = '/devices/metrics/controls/data_total_space'
        data_used_space_topic = '/devices/metrics/controls/data_used_space'
        dev_root_total_space_topic = '/devices/metrics/controls/dev_root_total_space'
        dev_root_used_space_topic = '/devices/metrics/controls/dev_root_used_space'

        def check_ip_10_200(ip_10_200, reg_num, dev_id_input):
            with open(config.file_200_txt, 'r', encoding='utf-8') as file:
                data = file.readlines()
                if dev_id_input == 'NONE': pass
                elif reg_num == 'None': pass
                else:
                    for line in data:
                        all_line_split = line.split()
                        if reg_num in line:
                            if ip_10_200 in line:
                                return True
                            elif ip_10_200 not in line:
                                with open(config.file_200_txt, 'r') as f:
                                    old_data = f.read()
                                new_line = ip_10_200 + ' ' + reg_num + ' ' + dev_id_input + '\n'
                                new_data = old_data.replace(line, new_line)
                                with open(config.file_200_txt, 'w') as f:
                                    f.write(new_data)
                                return False
                    else:
                        return None
        def write_new_ip_10_200(ip_10_200, reg_num, dev_id_input):
            new_line = ip_10_200 + ' ' + reg_num + ' ' + dev_id_input + '\n'
            with open(config.file_200_txt, 'a', encoding='utf8') as update:
                update.write(new_line)
                update.close()
                return True

        try:
            # кол-во соседей
            len_neigs_data = len_neighbors(reg_num)
            if len_neigs_data[0] == 0 and len_neigs_data[1] == 0:
                len_neigs = '0'
                len_his_neigs = '0'
            elif len_neigs_data[0] == 0 and len_neigs_data[1] != 0:
                len_neigs = '0'
                len_his_neigs = len(len_neigs_data[1])
            elif len_neigs_data[0] != 0 and len_neigs_data[1] == 0:
                len_neigs = len(len_neigs_data[0])
                len_his_neigs = '0'
            elif len_neigs_data[0] != 0 and len_neigs_data[1] != 0:
                len_neigs = len(len_neigs_data[0])
                len_his_neigs = len(len_neigs_data[1])

            def subscribe(client: mqtt_client):
                def on_message(client, userdata, msg):
                    if msg.topic == 'None':
                        print('нет данных ...')
                    elif msg.topic == vehicle_reg_num_topic:
                        alldata.update({str('vehicle_reg_num_topic'): msg.payload[0:]})
                    elif msg.topic == vin_topic:
                        alldata.update({str('vin'): str(msg.payload)[2:-1]})
                    elif msg.topic == la1_topic:
                        alldata.update({str('la1'): str(msg.payload)[2:-1]})
                    elif msg.topic == load_average_5min_topic:
                        alldata.update({str('load_average_5min_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == load_average_15min_topic:
                        alldata.update({str('load_average_15min_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == current_uptime_topic:
                        alldata.update({str('current_uptime_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == short_sn_topic:
                        alldata.update({str('short_sn_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == version_topic:
                        alldata.update({str('version_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == arm_device_topic:
                        alldata.update({str('arm_device_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == vpn_ip_topic:
                        alldata.update({str('vpn_ip_topic'): str(msg.payload)[2:-3]})
                    elif msg.topic == vpn_ip2_topic:
                        alldata.update({str('vpn_ip2_topic'): str(msg.payload)[2:-3]})
                    elif msg.topic == vpn_ip3_topic:
                        alldata.update({str('vpn_ip3_topic'): str(msg.payload)[2:-3]})
                    elif msg.topic == wifi_mac_topic:
                        alldata.update({str('wifi_mac_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == data_total_space_topic:
                        alldata.update({str('data_total_space_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == data_used_space_topic:
                        alldata.update({str('data_used_space_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == dev_root_total_space_topic:
                        alldata.update({str('dev_root_total_space_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == dev_root_used_space_topic:
                        alldata.update({str('dev_root_used_space_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == vehicle_type_topic:
                        alldata.update({str('vehicle_type_topic'): str(msg.payload)[2:-1]})
                    else:
                        print('error')

                    try:
                        vehicle_reg_num = 'reg_num: ' + alldata.get('vehicle_reg_num_topic').decode('utf-8')
                    except AttributeError:
                        vehicle_reg_num = 'reg_num: ' + 'None'
                    vin_result = 'vin: ' + str(alldata.get('vin'))
                    if str(alldata.get('vin')) != 'None':
                        if int(float(alldata.get('vin'))) < 12:
                            vin_result = 'vin: ' + str(alldata.get('vin')) + '❗️'

                    la1_result = 'la: ' + str(alldata.get('la1'))
                    if str(alldata.get('la1')) != 'None':
                        if int(float(alldata.get('la1'))) > 7:
                            la1_result = 'la: ' + str(alldata.get('la1')) + '❗️'
                    load_average_5min = ' | ' + str(alldata.get('load_average_5min_topic'))
                    if str(alldata.get('load_average_5min_topic')) != 'None':
                        if int(float(alldata.get('load_average_5min_topic'))) > 7:
                            load_average_5min = '' + str(alldata.get('load_average_5min_topic')) + '❗️'

                    load_average_15min = ' | ' + str(alldata.get('load_average_15min_topic'))
                    if str(alldata.get('load_average_15min_topic')) != 'None':
                        if int(float(alldata.get('load_average_15min_topic'))) > 7:
                            load_average_15min = '' + str(alldata.get('load_average_15min_topic')) + '❗️'

                    uplime = 'uptime: ' + str(alldata.get('current_uptime_topic'))
                    short_sn = 'sn: ' + str(alldata.get('short_sn_topic'))
                    if str(alldata.get('short_sn_topic')) == 'None':
                        short_sn = 'sn: ' + str(alldata.get('short_sn_topic')) + '❗️'
                    version_tg = 'version: ' + str(alldata.get('version_topic'))

                    arm_device = 'arm: ' + str(alldata.get('arm_device_topic'))
                    if str(alldata.get('arm_device_topic')) == 'None':
                        arm_device = 'arm: ' + str(alldata.get('arm_device_topic')) + '❗️'
                    elif str(alldata.get('arm_device_topic')) != 'None':
                        arm_device = 'arm: ' + 'ok'

                    wifi_mac = 'wi-fi mac: ' + str(alldata.get('wifi_mac_topic'))
                    if str(alldata.get('wifi_mac_topic')) == 'None':
                        wifi_mac = 'wi-fi mac: ' + str(alldata.get('wifi_mac_topic')) + '❗️'
                    dev_id = str(alldata.get('wifi_mac_topic'))
                    dev_id = dev_id.upper()


                    vpn_ip_1_address = str(alldata.get('vpn_ip_topic'))
                    vpn_ip_1 = 'vpn_1: ' + vpn_ip_1_address
                    if '10.200.' in vpn_ip_1_address:
                        if str(alldata.get('wifi_mac_topic')) != 'None' or str(alldata.get('wifi_mac_topic')) != 'NONE':
                            check = check_ip_10_200(vpn_ip_1_address, reg_num, dev_id)
                            if check == True:
                                vpn_ip_1 = 'vpn_1: ' + vpn_ip_1_address
                            elif check == False:
                                vpn_ip_1 = 'vpn_1: ' + vpn_ip_1_address + ' ⁉️'
                            elif check == None:
                                vpn_ip_1 = 'vpn_1: ' + vpn_ip_1_address + ' 🚫'
                                write_new_ip_10_200(vpn_ip_1_address, reg_num, dev_id)
                    elif vpn_ip_1_address == 'None':
                        vpn_ip_1 = 'vpn_1: ' + vpn_ip_1_address + '❗️'

                    vpn_ip_2_address = str(alldata.get('vpn_ip2_topic'))
                    vpn_ip_2 = 'vpn_2: ' + vpn_ip_2_address
                    if '10.200.' in vpn_ip_2_address:
                        if str(alldata.get('wifi_mac_topic')) != 'None':
                            check = check_ip_10_200(vpn_ip_2_address, reg_num, dev_id)
                            if check == True:
                                vpn_ip_2 = 'vpn_2: ' + vpn_ip_2_address
                            elif check == False:
                                vpn_ip_2 = 'vpn_2: ' + vpn_ip_2_address + ' ⁉️'
                            elif check == None:
                                vpn_ip_2 = 'vpn_2: ' + vpn_ip_2_address + ' 🚫'
                                write_new_ip_10_200(vpn_ip_2_address, reg_num, dev_id)
                    elif vpn_ip_2_address == 'None':
                        vpn_ip_2 = 'vpn_2: ' + str(alldata.get('vpn_ip2_topic')) + '❗️'

                    vpn_ip_3_address = str(alldata.get('vpn_ip3_topic'))
                    vpn_ip_3 = 'vpn_3: ' + vpn_ip_3_address
                    if '10.200.' in vpn_ip_3_address:
                        if str(alldata.get('wifi_mac_topic')) != 'None':
                            check = check_ip_10_200(vpn_ip_3_address, reg_num, dev_id)
                            if check == True:
                                vpn_ip_3 = 'vpn_3: ' + vpn_ip_3_address
                            elif check == False:
                                vpn_ip_3 = 'vpn_3: ' + vpn_ip_3_address + ' ⁉️'
                            elif check == None:
                                vpn_ip_3 = 'vpn_3: ' + vpn_ip_3_address + ' 🚫'
                                write_new_ip_10_200(vpn_ip_3_address, reg_num, dev_id)
                    elif vpn_ip_3_address == 'None':
                        vpn_ip_3 = 'vpn_3: ' + vpn_ip_3_address + '❗️'



                    data_space_tg = 'data: ' + str(alldata.get('data_total_space_topic'))
                    data_root_tg = 'root: ' + str(alldata.get('dev_root_total_space_topic'))
                    root_total = str(alldata.get('dev_root_total_space_topic'))
                    root_used = str(alldata.get('dev_root_used_space_topic'))
                    if root_total == 'None' or root_total == None or root_used == 'None' or root_used == None:
                        tg_root_free_procent = ''
                        pass
                    elif root_total != 'None' or root_total != None and root_used != 'None' or root_used != None:
                        procent_used = int(root_used) / int(root_total) * 100
                        procent_free = str(100 - int(procent_used))
                        tg_root_free_procent = f' | free: {procent_free}%'
                        if int(procent_free) < 15:
                            tg_root_free_procent = f' | free: {procent_free}% ❗️'
                    data_total = str(alldata.get('data_total_space_topic'))
                    data_used = str(alldata.get('data_used_space_topic'))
                    if data_total == 'None' or data_total == None or data_used == 'None' or data_used == None:
                        tg_data_free_procent = ''
                        pass
                    elif data_total != 'None' or data_total != None and data_used != 'None' or data_used != None:
                        procent_used = int(data_used) / int(data_total) * 100
                        procent_free = str(100 - int(procent_used))
                        tg_data_free_procent = f' | free: {procent_free}%'

                    neighbors = f'neighbors: {len_neigs}|{len_his_neigs}'
                    if len_neigs != len_his_neigs:
                        neighbors = f'neighbors: {len_neigs}|{len_his_neigs} ❗️'

                    if str(alldata.get('vehicle_type_topic')) == 'C010':
                        vehicle_type = 'C010: Бункер перегрузчик'
                    elif str(alldata.get('vehicle_type_topic')) == 'C020':
                        vehicle_type = 'C020: Уборочная техника'
                    elif str(alldata.get('vehicle_type_topic')) == 'C030':
                        vehicle_type = 'C030: Свеклоуборочная техника'
                    elif str(alldata.get('vehicle_type_topic')) == 'C031':
                        vehicle_type = 'C031: Свеклотранспортёр'
                    elif str(alldata.get('vehicle_type_topic')) == 'C070':
                        vehicle_type = 'C070: Свеклопогрузочная техника'
                    elif str(alldata.get('vehicle_type_topic')) == 'D025':
                        vehicle_type = 'D025: Топливозаправщик'
                    else:
                        vehicle_type = 'vehicle_type: ' + str(alldata.get('vehicle_type_topic'))


                    result_tg = f"{vehicle_reg_num}\n{vin_result}\n{la1_result}{load_average_5min}{load_average_15min}\n{uplime}\n{short_sn}\n{version_tg}\n{arm_device}\n{neighbors}\n{vehicle_type}\n{vpn_ip_1}\n{vpn_ip_2}\n{vpn_ip_3}\n{wifi_mac}\n{data_root_tg}{tg_root_free_procent}\n{data_space_tg}{tg_data_free_procent}\n"

                    function_ping = str('function_ping ' + ip + ' ' + reg_num)
                    function_mqtt_about_system = str('function_mqtt_about_system ' + ip + ' ' + reg_num)
                    function_mqtt_about_sensors = str('function_mqtt_about_sensors ' + ip + ' ' + reg_num)
                    function_get_neighbors = str('function_get_neighbors ' + ip + ' ' + reg_num)
                    function_broadcast_config_create = str('broad_create ' + ip + ' ' + reg_num)
                    function_tagpack_config_create = str('tag_create ' + ip + ' ' + reg_num + ' ' + short_sn)
                    fix_vpn = str('fix_vpn ' + ' ' + ip + ' ' + reg_num + ' ' + dev_id)
                    sleep = str('sleep ' + ip + ' ' + reg_num)
                    tag_storage = str('tag_storage ' + ip + ' ' + reg_num + ' ' + dev_id)
                    check_configs_read = str('check_configs_read ' + ip + ' ' + reg_num + ' ' + short_sn.split()[1])
                    reboot_wirenboard_send = str('reboot_wirenboard ' + ip + ' ' + reg_num)

                    keyboard = types.InlineKeyboardMarkup()
                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                    callback_button_about_system = types.InlineKeyboardButton(text="о системе", callback_data=function_mqtt_about_system)
                    callback_button_about_sensors = types.InlineKeyboardButton(text="об оборудовании", callback_data=function_mqtt_about_sensors)
                    callback_button_broadcast_config_create = types.InlineKeyboardButton(text="бродкасты", callback_data=function_broadcast_config_create)
                    callback_button_tagpack_config_create = types.InlineKeyboardButton(text="таг пак", callback_data=function_tagpack_config_create)
                    callback_button_get_neighbors = types.InlineKeyboardButton(text="соседи", callback_data=function_get_neighbors)
                    callback_button_fix_vpn = types.InlineKeyboardButton(text="исправить впн`ы", callback_data=fix_vpn)
                    callback_button_tag_storage = types.InlineKeyboardButton(text="о справочниках", callback_data=tag_storage)
                    callback_button_check_configs_read = types.InlineKeyboardButton(text="проверить конфиги", callback_data=check_configs_read)
                    callback_button_reboot_wirenboard_send = types.InlineKeyboardButton(text="перезагрузить", callback_data=reboot_wirenboard_send)
                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')


                    if call.message.chat.username in config.users or config.admins:
                        # if vehicle_type == 'C070' or vehicle_type == 'C030' or vehicle_type == 'C031': # свекла
                        if len_neigs == '0' and len_his_neigs == '0':
                            keyboard.add(callback_button_about_system, callback_button_about_sensors)
                            keyboard.add(callback_button_broadcast_config_create, callback_button_tagpack_config_create)
                            keyboard.add(callback_button_fix_vpn, callback_button_reboot_wirenboard_send)
                            keyboard.add(callback_button_check_configs_read, callback_button_tag_storage)
                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)

                        else:
                            keyboard.add(callback_button_about_system, callback_button_about_sensors)
                            keyboard.add(callback_button_broadcast_config_create, callback_button_tagpack_config_create, callback_button_get_neighbors)
                            keyboard.add(callback_button_fix_vpn, callback_button_reboot_wirenboard_send)
                            keyboard.add(callback_button_check_configs_read, callback_button_tag_storage)
                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)

                        try:
                            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                  text=f'{call.message.text}\n\n{result_tg}', reply_markup=keyboard)
                        except telebot.apihelper.ApiTelegramException as e:
                            print('- error code: ', e.error_code)
                            if e.error_code == 429:
                                client.disconnect()
                                print(' - пиздец. слишком много запросов, ожидай, 180 секунд максимум блокировка.')
                            elif e.error_code == 400:
                                print(' - не обращай внимания ...')
                                client.disconnect()
                            pass
                    else:
                        print(f'у {call.message.from_user.username} нет доступа')

                alldata = {}

                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n - connect!')

                client.subscribe(vehicle_reg_num_topic)
                client.subscribe(vin_topic)
                client.subscribe(la1_topic)
                client.subscribe(load_average_5min_topic)
                client.subscribe(load_average_15min_topic)
                client.subscribe(current_uptime_topic)
                client.subscribe(short_sn_topic)
                client.subscribe(version_topic)
                client.subscribe(arm_device_topic)
                client.subscribe(vehicle_type_topic)
                client.subscribe(wifi_mac_topic)
                client.subscribe(vpn_ip_topic)
                client.subscribe(vpn_ip2_topic)
                client.subscribe(vpn_ip3_topic)
                client.subscribe(dev_root_total_space_topic)
                client.subscribe(dev_root_used_space_topic)
                client.subscribe(data_total_space_topic)
                client.subscribe(data_used_space_topic)

                client.on_message = on_message

            def run():
                try:
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{call.message.text}\n - connect to {ip} ... ')
                    client = connect_mqtt(broker)
                    if client == TimeoutError:
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n - TimeoutError ...\n - повторяю попытку ...')
                        time.sleep(3)
                        client = connect_mqtt(broker)

                        if client == TimeoutError:
                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                  text=f'{call.message.text}\n - TimeoutError!\n - TimeoutError!', reply_markup=keyboard)
                        elif client != TimeoutError:
                            subscribe(client)
                            client.loop_start()
                            time.sleep(8)
                            client.disconnect()

                    elif client != TimeoutError:
                        print('\n - client - connect!')
                        subscribe(client)
                        client.loop_start()
                        time.sleep(5)
                        client.disconnect()
                        print(' - client - disconnect!\n')

                except Exception as e:
                    print('\n - connect_mqtt(broker): ', traceback.format_exc(), '\n')
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n - Exception: {e.with_traceback()}', reply_markup=keyboard)

            run()

        except TimeoutError:
            print('pizdec, a ne data')
            # todo добавить следить
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n - TimeoutError\n - либо адрес сменился, либо связь говно.',
                                  reply_markup=keyboard)
        except telebot.apihelper.ApiTelegramException as e:
            print()
            print('- error code: ', e.error_code)
            print(' - traceback telebot.apihelper.ApiException: ', traceback.format_exc())
            print()

        except Exception:
            print('\n - traceback Exception 2: ', traceback.format_exc(), '\n')

    # инфо через соседа по бродкасту
    elif 'i_mqtt_heig' in call.data:
        print('info_mqtt_heighbors_about')
        input_tg = call.data.split()
        ip = input_tg[1]
        reg_num = input_tg[2]
        ip_broadcast = input_tg[3]

        command = f"""ping -s 32 -c 1 {ip_broadcast};
                        mosquitto_sub -C 1 -h {ip_broadcast} -t '/devices/vehicle/controls/sim_card';
                        mosquitto_sub -C 1 -h {ip_broadcast} -t '/devices/vehicle/controls/sim_mode';
                        mosquitto_sub -C 1 -h {ip_broadcast} -t '/devices/vehicle/controls/iccid_sim_1';
                        mosquitto_sub -C 1 -h {ip_broadcast} -t '/devices/vehicle/controls/iccid_sim_2';
                        mosquitto_sub -C 1 -h {ip_broadcast} -t '/devices/network/controls/GPRS IP'"""


        try:
            threadname = f'about_neighbor {ip_broadcast} | {call.message.chat.username}'
            thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                      args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 120])
            thread.start()
            thread.join()

            result_data = thread.result
        except paramiko.ssh_exception.AuthenticationException:
            result_data = ' - timeout'
        except TimeoutError:
            print('\n - ! timeout error обработан, как ошибка ! - \n')
            result_data = ' - timeout'
        except AttributeError:
            result_data = ' - timeout'
        print()

        print(' --- ', input_tg, ' === ', result_data)
        if result_data == TimeoutError:
            print('\n - ! timeout error обработан, как условие ! - \n')

        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                              text=f'{call.message.text}\n\n{result_data}')
        # if result_data == TimeoutError:
        #     print('\n - ! timeout error обработан ! - \n')

        # print()

        # todo выводим данные в тг
        # todo кнопки: сменить симку, перезагрузить | через такого соседа, на выбор

    # об оборудовании
    elif 'function_mqtt_about_sensors' in call.data:
        try:
            input = call.data.split()
            broker = input[1]
            reg_num = input[2]
            ip = broker

            vehicle_reg_num_topic = '/devices/vehicle/controls/_vehicle_reg_num'
            vehicle_type_topic = '/devices/vehicle/controls/vehicle_type'
            sim_card_topic = '/devices/vehicle/controls/sim_card'
            sim_operator_topic = '/devices/vehicle/controls/sim_operator'
            # rat_mode_topic = '/devices/vehicle/controls/rat_mode'
            # RSSI_dBm_topic = '/devices/vehicle/controls/RSSI_dBm'
            iccid_sim_1_topic = '/devices/vehicle/controls/iccid_sim_1'
            iccid_sim_2_topic = '/devices/vehicle/controls/iccid_sim_2'

            rfid_1_topic = '/devices/vehicle/controls/RFID_1'
            rfid_2_topic = '/devices/vehicle/controls/RFID_2'

            bunker_level_topic = '/devices/vehicle/controls/bunker_level'
            # bunker_level_sens_topic = '/devices/vehicle/controls/bunker_level_sens'
            unloader_bypass_topic = '/devices/vehicle/controls/unloader_bypass'
            unloader_arm_topic = '/devices/vehicle/controls/unloader_arm'
            unloader_rotate_topic = '/devices/vehicle/controls/unloader_rotate'
            unloader_freq_topic = '/devices/vehicle/controls/unloader_freq'
            loader_rotate_topic = '/devices/vehicle/controls/loader_rotate'
            dg400_topic = '/devices/vehicle/controls/DG400'
            can_wdog_topic = '/devices/vehicle/controls/CAN_WDOG'
            modbus_topic = '/devices/vehicle/controls/ModBUS_OK'

            def subscribe(client: mqtt_client):
                def on_message(client, userdata, msg):
                    if msg.topic == 'None':
                        print('нет данных ...')

                    elif msg.topic == vehicle_reg_num_topic:
                        alldata.update({str('vehicle_reg_num_topic'): msg.payload[0:]})
                    elif msg.topic == vehicle_type_topic:
                        alldata.update({str('vehicle_type_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == sim_card_topic:
                        alldata.update({str('sim_card_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == sim_operator_topic:
                        alldata.update({str('sim_operator_topic'): str(msg.payload)[2:-1]})
                    # elif msg.topic == rat_mode_topic:
                    #     alldata.update({str('rat_mode_topic'): str(msg.payload)[2:-1]})
                    # elif msg.topic == RSSI_dBm_topic:
                    #     alldata.update({str('RSSI_dBm_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == iccid_sim_1_topic:
                        alldata.update({str('iccid_sim_1_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == iccid_sim_2_topic:
                        alldata.update({str('iccid_sim_2_topic'): str(msg.payload)[2:-1]})

                    elif msg.topic == bunker_level_topic:
                        alldata.update({str('bunker_level_topic'): str(msg.payload)[2:-1]})
                    # elif msg.topic == bunker_level_sens_topic:
                    #     alldata.update({str('bunker_level_sens_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == unloader_bypass_topic:
                        alldata.update({str('unloader_bypass_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == unloader_freq_topic:
                        alldata.update({str('unloader_freq_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == loader_rotate_topic:
                        alldata.update({str('loader_rotate_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == unloader_arm_topic:
                        alldata.update({str('unloader_arm_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == unloader_rotate_topic:
                        alldata.update({str('unloader_rotate_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == unloader_freq_topic:
                        alldata.update({str('unloader_freq_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == dg400_topic:
                        alldata.update({str('dg400_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == can_wdog_topic:
                        alldata.update({str('can_wdog_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == modbus_topic:
                        alldata.update({str('modbus_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == rfid_1_topic:
                        alldata.update({str('rfid_1_topic'): str(msg.payload)[2:-1]})
                    elif msg.topic == rfid_2_topic:
                        alldata.update({str('rfid_2_topic'): str(msg.payload)[2:-1]})
                    else:
                        print('error')

                    vehicle_reg_num = 'reg_num: ' + str(alldata.get('vehicle_reg_num_topic').decode('utf-8'))
                    vehicle_type = str(alldata.get('vehicle_type_topic'))
                    vehicle_type_tg = 'vehicle_type: ' + str(alldata.get('vehicle_type_topic'))
                    sim_card = 'sim_card: ' + str(alldata.get('sim_card_topic'))
                    sim_operator = 'sim_operator: ' + str(alldata.get('sim_operator_topic'))
                    iccid_sim_1 = 'iccid_1: ' + str(alldata.get('iccid_sim_1_topic'))
                    iccid_sim_2 = 'iccid_2: ' + str(alldata.get('iccid_sim_2_topic'))

                    bunker_level = 'bunker: ' + str(alldata.get('bunker_level_topic'))
                    unloader_bypass = 'unloader_bypass: ' + str(alldata.get('unloader_bypass_topic'))
                    unloader_arm = 'unloader_arm: ' + str(alldata.get('unloader_arm_topic'))
                    unloader_rotate = 'unloader_rotate: ' + str(alldata.get('unloader_rotate_topic'))
                    unloader_freq = 'unloader_freq: ' + str(alldata.get('unloader_freq_topic'))
                    loader_rotate = 'loader_rotate: ' + str(alldata.get('loader_rotate_topic'))
                    dg400 = 'dg400: ' + str(alldata.get('dg400_topic'))
                    can_wdog = 'can_wdog: ' + str(alldata.get('can_wdog_topic'))
                    modbus = 'modbus: ' + str(alldata.get('modbus_topic'))
                    rfids = 'rfid`ы: ' + str(alldata.get('rfid_1_topic')) + ' / ' + str(alldata.get('rfid_2_topic'))

                    # rat_mode = 'rat_mode: ' + str(alldata.get('rat_mode_topic'))
                    # RSSI_dBm = 'RSSI_dBm: ' + str(alldata.get('RSSI_dBm_topic'))
                    # bunker_level_sens_data_1 = bunker_level_sens_data
                    # bunker_level_sens = 'bunker_sens: ' + str(alldata.get('bunker_level_sens_topic'))
                    # bunker_level_sens_data = alldata.get('bunker_level_sens_topic')
                    # print(" - bunker_level_sens_data: ", bunker_level_sens_data_1)

                    result_tg = f"Об оборудовании:\n{vehicle_reg_num}\n{vehicle_type_tg}\n{sim_card}\n{sim_operator}\n{iccid_sim_1}\n{iccid_sim_2}\n\n{bunker_level}\n{unloader_bypass}\n{unloader_arm}\n{unloader_rotate}\n{unloader_freq}\n{loader_rotate}\n{dg400}\n{can_wdog}\n{modbus}\n{rfids}\n"

                    function_ping = str('function_ping ' + ip + ' ' + reg_num)
                    function_mqtt_about_system = str('function_mqtt_about_system ' + ip + ' ' + reg_num)
                    function_mqtt_about_sensors = str('function_mqtt_about_sensors ' + ip + ' ' + reg_num)
                    sleep = str('sleep ' + ip + ' ' + reg_num)
                    can_read = str('can_read ' + ip + ' ' + reg_num)
                    keyboard = types.InlineKeyboardMarkup()
                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                    callback_button_about_system = types.InlineKeyboardButton(text="о системе",
                                                                              callback_data=function_mqtt_about_system)
                    callback_button_about_sensors = types.InlineKeyboardButton(text="об оборудовании",
                                                                               callback_data=function_mqtt_about_sensors)
                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                    callback_button_can_read = types.InlineKeyboardButton(text="проверка CAN", callback_data=can_read)


                    can_read = str('can_read ' + ip + ' ' + reg_num)
                    if vehicle_type == 'C070' or vehicle_type == 'C030' or vehicle_type == 'C031':
                        print(' - THIS IS SVEKLA! ..... ', vehicle_type)
                        keyboard.add(callback_button_about_system, callback_button_about_sensors)
                        keyboard.add(callback_button_can_read)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    else:
                        print(' - this is', vehicle_type, '...')
                        keyboard.add(callback_button_about_system, callback_button_about_sensors)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)

                    try:
                        time.sleep(0.1)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n{result_tg}', reply_markup=keyboard)
                    except telebot.apihelper.ApiTelegramException as e:
                        print('- error code: ', e.error_code)
                        if e.error_code == 429:
                            client.disconnect()
                            print(' - пиздец. слишком много запросов, ожидай, максимум 180 секунд блокировка.')
                            time.sleep(1)
                        elif e.error_code == 400:
                            client.disconnect()
                            print(' - не обращай внимания ...')
                            pass

                alldata = {}
                client.subscribe(vehicle_reg_num_topic)
                client.subscribe(vehicle_type_topic)
                client.subscribe(sim_card_topic)
                client.subscribe(sim_operator_topic)
                # client.subscribe(rat_mode_topic)
                # client.subscribe(RSSI_dBm_topic)
                client.subscribe(iccid_sim_1_topic)
                client.subscribe(iccid_sim_2_topic)

                client.subscribe(bunker_level_topic)
                # client.subscribe(bunker_level_sens_topic)
                client.subscribe(unloader_bypass_topic)
                client.subscribe(unloader_arm_topic)
                client.subscribe(unloader_rotate_topic)
                client.subscribe(unloader_freq_topic)
                client.subscribe(loader_rotate_topic)
                client.subscribe(dg400_topic)
                client.subscribe(can_wdog_topic)
                client.subscribe(modbus_topic)
                client.subscribe(rfid_1_topic)
                client.subscribe(rfid_2_topic)

                client.on_message = on_message

            def run():
                try:
                    try:
                        client = connect_mqtt(broker)
                    except telebot.apihelper.ApiTelegramException:
                        print()
                        print(' - traceback telebot.apihelper.ApiTelegramException в client = connect_mqtt(broker): ',
                              traceback.format_exc())
                        print()
                        client = False
                    try:
                        subscribe(client)
                    except telebot.apihelper.ApiTelegramException:
                        print()
                        print(' - traceback telebot.apihelper.ApiTelegramException в subscribe(client): ',
                              traceback.format_exc())
                        print()

                    client.loop_start()
                    time.sleep(5)
                    client.disconnect()
                    print('client.disconnect')

                except TimeoutError:
                    # while True:
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n - TimeoutError, - restart ...')
                    time.sleep(3)
                    try:
                        client = connect_mqtt(broker)
                        subscribe(client)
                        client.loop_start()
                        time.sleep(7)
                        client.disconnect()
                    except TimeoutError:
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n - TimeoutError, - restart ...\n - TimeoutError, - restart ...')
                        time.sleep(3)
                        try:
                            client = connect_mqtt(broker)
                            subscribe(client)
                            client.loop_start()
                            time.sleep(7)
                            client.disconnect()
                        except TimeoutError:
                            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                  text=f'{call.message.text}\n - TimeoutError, - restart ... \n - TimeoutError, - restart ... \n - TimeoutError, - the end.')
                except telebot.apihelper.ApiTelegramException as e:
                    print()
                    print('- error code: ', e.error_code)
                    print(' - traceback telebot.apihelper.ApiTelegramException - main: ', traceback.format_exc())
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f' - ошибка main:\n{traceback.format_exc()}')
                    print()
                except Exception:
                    print()
                    print(' - traceback Exception: ', traceback.format_exc())
                    print()

            run()
        except TimeoutError:
            print('pizdec, a ne data')
            input = call.data.split()
            ip = input[1]
            reg_num = input[2]
            function_ping = str('function_ping ' + ip + ' ' + reg_num)
            callback_button = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
            keyboard = types.InlineKeyboardMarkup()
            keyboard.add(callback_button)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n - TimeoutError\n - либо адрес сменился, либо связь говно.',
                                  reply_markup=keyboard)
        except telebot.apihelper.ApiTelegramException as e:
            print()
            print('- error code: ', e.error_code)
            print(' - traceback telebot.apihelper.ApiException: ', traceback.format_exc())
            print()
        except Exception:
            print()
            print(' - traceback Exception: ', traceback.format_exc())
            print()

    # создать таг пак из таблиц гугл
    elif 'tag_create' in call.data:
        input_tg = call.data.split()
        print(input_tg)
        ip = input_tg[1]
        reg_num = input_tg[2]
        short_sn = input_tg[4]
        spreadsheet_id = config.tagpack_spreadsheet_id
        range_var = 'B2:E1000'
        major = 'ROWS'
        sheet = google_sheets_read(spreadsheet_id, range_var, major)

        for row in sheet:
            if short_sn in row:
                print(row)
                dev_id = row[1]
                dev_id_pass = row[2]

                tackpack_config_file = f'tag_address = "194.226.138.63";\ntag_port = "48888";\npublic_key_path = "/opt/tagpack-server/tagpack.pem";\nstorage_path = "/opt/tag_storage";\nport = "8080";\ntag_timeout = "20000";\ntag_device_number = "{dev_id}";\ntag_device_secret = "{dev_id_pass}";\narchive_mode = false;'
                function_ping = str('function_ping ' + ip + ' ' + reg_num)
                sleep = str('sleep ' + ip + ' ' + reg_num)
                function_tackpack_config_send = str('tag_send ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                # print('function_tackpack_config_send: ', function_tackpack_config_send)
                keyboard = types.InlineKeyboardMarkup()

                callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                callback_button_send_tagpack = types.InlineKeyboardButton(text="исправить таг пак",
                                                                          callback_data=f'{function_tackpack_config_send}')
                keyboard.add(callback_button_send_tagpack)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\nданные из таблицы:\n{tackpack_config_file}\n\nnano /etc/tagpack-server/config\nsystemctl restart tagpack_server\njournalctl -u tagpack_server  --follow\n',
                                      reply_markup=keyboard)

    # создать бродкаст из таблиц гугл
    elif 'broad_create' in call.data:
        input_tg = call.data.split()
        print(input_tg)
        ip = input_tg[1]
        reg_num = input_tg[2]
        # ip = call.message.text.split()[0]

        spreadsheet_id = config.broadcast_spreadsheet_id
        major = 'ROWS'

        range_belgorod = 'Белгород!A2:D255'  # 'Sheet2!A2:E10'
        sheet_broadcats_belgorog = google_sheets_read(spreadsheet_id, range_belgorod, major)
        range_kursk = 'Курск!A2:D255'
        sheet_broadcats_kursk = google_sheets_read(spreadsheet_id, range_kursk, major)
        range_tambov = 'Тамбов!A2:D255'
        sheet_broadcats_tambov = google_sheets_read(spreadsheet_id, range_tambov, major)
        range_orel = 'Орел!A2:D255'
        sheet_broadcats_orel = google_sheets_read(spreadsheet_id, range_orel, major)
        range_primorie = 'Приморье!A2:D255'
        sheet_broadcats_primorie = google_sheets_read(spreadsheet_id, range_primorie, major)

        for row in sheet_broadcats_belgorog:
            if reg_num in row:
                reg_num_from_sheet = row[0]
                broadcast_ip = row[1]
                mikrotik_ip = row[2]
                mikrotik_ip_2 = ''
                result_tg = f'{call.message.text}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip} {mikrotik_ip_2}\n\ncat /etc/network/interfaces.d/broadcast_interface\n/interface wireless print advanced\n/interface wireless registration-table print interval=5\n'
                function_ping = str('function_ping ' + ip + ' ' + reg_num)
                sleep = str('sleep ' + ip + ' ' + reg_num)
                broadcast_send = str('broad_send ' + ip + ' ' + reg_num + ' ' + broadcast_ip)
                keyboard = types.InlineKeyboardMarkup()
                callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст",
                                                                            callback_data=broadcast_send)
                callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                keyboard.add(callback_button_send_broadcast)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=result_tg,
                                      reply_markup=keyboard)

        for row in sheet_broadcats_kursk:
            if reg_num in row:
                reg_num_from_sheet = row[0]
                broadcast_ip = row[1]
                mikrotik_ip = row[2]
                mikrotik_ip_2 = ''
                result_tg = f'{call.message.text}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip} {mikrotik_ip_2}\n\ncat /etc/network/interfaces.d/broadcast_interface\n/interface wireless print advanced\n/interface wireless registration-table print interval=5\n'
                function_ping = str('function_ping ' + ip + ' ' + reg_num)
                sleep = str('sleep ' + ip + ' ' + reg_num)
                broadcast_send = str('broad_send ' + ip + ' ' + reg_num + ' ' + broadcast_ip)
                keyboard = types.InlineKeyboardMarkup()
                callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст",
                                                                            callback_data=broadcast_send)
                callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                keyboard.add(callback_button_send_broadcast)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=result_tg,
                                      reply_markup=keyboard)

        for row in sheet_broadcats_tambov:
            if reg_num in row:
                reg_num_from_sheet = row[0]
                broadcast_ip = row[1]
                mikrotik_ip = row[2]
                mikrotik_ip_2 = ''
                result_tg = f'{call.message.text}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip} {mikrotik_ip_2}\n\ncat /etc/network/interfaces.d/broadcast_interface\n/interface wireless print advanced\n/interface wireless registration-table print interval=5\n'
                function_ping = str('function_ping ' + ip + ' ' + reg_num)
                sleep = str('sleep ' + ip + ' ' + reg_num)
                broadcast_send = str('broad_send ' + ip + ' ' + reg_num + ' ' + broadcast_ip)
                keyboard = types.InlineKeyboardMarkup()
                callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст",
                                                                            callback_data=broadcast_send)
                callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                keyboard.add(callback_button_send_broadcast)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=result_tg,
                                      reply_markup=keyboard)

        for row in sheet_broadcats_orel:
            if reg_num in row:
                reg_num_from_sheet = row[0]
                broadcast_ip = row[1]
                mikrotik_ip = row[2]
                mikrotik_ip_2 = ''
                result_tg = f'{call.message.text}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip} {mikrotik_ip_2}\n\ncat /etc/network/interfaces.d/broadcast_interface\n/interface wireless print advanced\n/interface wireless registration-table print interval=5\n'
                function_ping = str('function_ping ' + ip + ' ' + reg_num)
                sleep = str('sleep ' + ip + ' ' + reg_num)
                broadcast_send = str('broad_send ' + ip + ' ' + reg_num + ' ' + broadcast_ip)
                keyboard = types.InlineKeyboardMarkup()
                callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст",
                                                                            callback_data=broadcast_send)
                callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                keyboard.add(callback_button_send_broadcast)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=result_tg,
                                      reply_markup=keyboard)

        for row in sheet_broadcats_primorie:
            if reg_num in row:
                reg_num_from_sheet = row[0]
                broadcast_ip = row[1]
                mikrotik_ip = row[2]
                mikrotik_ip_2 = ''
                result_tg = f'{call.message.text}\n\nданные из таблицы:\nreg_num: {reg_num_from_sheet}\nbroadcast_ip: {broadcast_ip}\nmikrotik_ip: {mikrotik_ip} {mikrotik_ip_2}\n\ncat /etc/network/interfaces.d/broadcast_interface\n/interface wireless print advanced\n/interface wireless registration-table print interval=5\n'
                function_ping = str('function_ping ' + ip + ' ' + reg_num)
                sleep = str('sleep ' + ip + ' ' + reg_num)
                broadcast_send = str('broad_send ' + ip + ' ' + reg_num + ' ' + broadcast_ip)
                keyboard = types.InlineKeyboardMarkup()
                callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст",
                                                                            callback_data=broadcast_send)
                callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                keyboard.add(callback_button_send_broadcast)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=result_tg,
                                      reply_markup=keyboard)

    # исправить таг пак
    elif 'tag_send' in call.data:
        print('data: ', call.data)
        # print('message.text: ', call.message.text)
        input_tg = call.data.split()
        ip = input_tg[1]
        # ip = '192.168.0.97'
        reg_num = input_tg[2]
        dev_id = input_tg[3]
        dev_id_pass = input_tg[4]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        command = f"""echo 'tag_address = \"194.226.138.63\";\ntag_port = \"48888\";\npublic_key_path = \"/opt/tagpack-server/tagpack.pem\";\nstorage_path = \"/opt/tag_storage\";\nport = \"8080\";\ntag_timeout = \"20000\";\ntag_device_number = \"{dev_id}\";\ntag_device_secret = \"{dev_id_pass}\";\narchive_mode = false;' > /etc/tagpack-server/config; systemctl restart tagpack_server"""
        print(command)

        threadname = f'tackpack_send {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            result = thread.result
            print(' - thread.result: ', thread.result)

            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг таг пака исправлен.', reply_markup=keyboard)
            elif result == TimeoutError:
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...')
                thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                          args=[ip, config.wirenboard_username, config.wirenboard_password, command, 120, 120])
                thread.start()
                thread.join()
                try:
                    result = thread.result
                    print(thread.result)

                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг таг пака исправлен.', reply_markup=keyboard)
                    elif result == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n -  TimeoutError!\n - ничего не отправил.', reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - хуйня какая-то, нет такого условия ...\n\nresult:\n{result}',
                                              reply_markup=keyboard)
                except AttributeError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n -  AttributeError!\n - ничего не отправил.', reply_markup=keyboard)

            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - хуйня какая-то, нет такого условия ...\n\nresult:\n{result}', reply_markup=keyboard)
        except AttributeError:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повторяю попытку ...')
            thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 120, 120])
            thread.start()
            thread.join()

            try:
                result = thread.result
                print(thread.result)

                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг таг пака исправлен.', reply_markup=keyboard)
                elif result == TimeoutError:
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...')
                    thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                              args=[ip, config.wirenboard_username, config.wirenboard_password, command, 120, 120])
                    thread.start()
                    thread.join()

                    try:
                        result = thread.result
                        print(thread.result)

                        if result == []:
                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                  text=f'{call.message.text}\n\n - конфиг таг пака исправлен.', reply_markup=keyboard)
                        elif result == TimeoutError:
                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                  text=f'{call.message.text}\n\n - TimeoutError!\n -  TimeoutError!\n - ничего не отправил.',
                                                  reply_markup=keyboard)
                        else:
                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                  text=f'{call.message.text}\n\n - хуйня какая-то, нет такого условия ...\n\n - result:\n{result}',
                                                  reply_markup=keyboard)

                    except AttributeError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n -  AttributeError!\n - ничего не отправил.', reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - хуйня какая-то, нет такого условия ...\n\n - result:\n{result}', reply_markup=keyboard)

            except AttributeError:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n -  AttributeError!\n - ничего не отправил.', reply_markup=keyboard)
        except Exception:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{result}', reply_markup=keyboard)

    # исправить бродкаст
    elif 'broad_send' in call.data:
        input_tg = call.data.split()
        print(input_tg)
        ip = input_tg[1]
        reg_num = input_tg[2]
        broadcast_ip = input_tg[3]

        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        reboot_wirenboard_send = str('reboot_wirenboard ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
        callback_button_reboot_wirenboard_send = types.InlineKeyboardButton(text="перезагрузить", callback_data=reboot_wirenboard_send)

        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{call.message.text}\n - подключаюсь к {ip} ...')

        command = f"""echo 'auto eth0\niface eth0 inet static\n  address {broadcast_ip}\n  netmask 255.255.248.0' > /etc/network/interfaces.d/broadcast_interface;systemctl restart broadcast_server;systemctl restart broadcast_client"""
        threadname = f'broadcast_send {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 30, 30])
        thread.start()
        thread.join()

        try:
            result = thread.result
            print(' - thread.result: ', result)

            if result == []:
                keyboard.add(callback_button_reboot_wirenboard_send)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг бродкаста исправлен.\n - службы перезапущены.', reply_markup=keyboard)

            elif result == TimeoutError:
                print(' - result in TimeoutError: ', result)
                thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError ... \n - повторяю попытку ...', reply_markup=keyboard)
                thread.start()
                thread.join()

                try:
                    result = thread.result
                    print(result)

                    if result == []:
                        keyboard.add(callback_button_reboot_wirenboard_send)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг бродкаста исправлен.\n - службы перезапущены.', reply_markup=keyboard)
                    elif result == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - отправить данные не удалось.',
                                              reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_reboot_wirenboard_send)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
                except AttributeError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - AttributeError!\n - отправить данные не удалось.',
                                          reply_markup=keyboard)

            else:
                keyboard.add(callback_button_reboot_wirenboard_send)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
        except AttributeError:
            thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - TimeoutError ... \n - повторяю попытку ...', reply_markup=keyboard)
            thread.start()
            thread.join()

            try:
                result = thread.result
                print(result)

                if result == []:
                    keyboard.add(callback_button_reboot_wirenboard_send)
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг бродкаста исправлен.\n - службы перезапущены.', reply_markup=keyboard)
                elif result == TimeoutError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - TimeoutError!\n - отправить данные не удалось.',
                                          reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_reboot_wirenboard_send)
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except AttributeError:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - AttributeError!\n - отправить данные не удалось.',
                                      reply_markup=keyboard)
        except Exception:
            keyboard.add(callback_button_reboot_wirenboard_send)
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n - result:\n{result}', reply_markup=keyboard)

    # исправить конфиг деплоя - сервер
    elif 'deploy_send' in call.data:
        ip = call.data.split()[1]
        reg_num = call.data.split()[2]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{call.message.text}\n\n - подключаюсь к {ip} ...')

        command = f"""echo 'local_repo_path = "/mnt/data/local_repo";\ndeploy_server_port = "8181";\nrunning_software_path = "/mnt/data/bin";\nremote_repo_address = "http://10.100.128.1:8080";\nmqtt_agent_address = "http://127.0.0.1:9194";\ndeploy_policy = "sspti";\nsqlite_path = "/mnt/data/root/mqtt_agent/data.db3";\nmqtt_host = "localhost:1883";' > /etc/deploy-server/config; systemctl restart deploy_server"""
        threadname = f'deploy_config_send {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 30, 30])
        thread.start()
        thread.join()

        try:
            result = thread.result

            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг деплоя исправлен.', reply_markup=keyboard)
            elif result == TimeoutError:
                print('\n - deploy send ', ip, reg_num, '- TimeoutError\n')
                print(' - повтор подключения к ', ip, '...')
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повтор подключения к ...')
                thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
                thread.start()
                thread.join()

                try:
                    result = thread.result
                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг деплоя исправлен.', reply_markup=keyboard)
                    elif result == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - отправить конфиг деплоя не удалось ...', reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет такого условия!\n\nresult:\n{result}', reply_markup=keyboard)
                except AttributeError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - AttributeError:\n{result}\n - отправить конфиг деплоя не удалось ...',
                                          reply_markup=keyboard)
            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет такого условия!\n\nresult:\n{result}', reply_markup=keyboard)
        except AttributeError:
            print(' - повтор подключения к ', ip, '...')
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повтор подключения к ...')
            thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
            thread.start()
            thread.join()

            try:
                result = thread.result
                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг деплоя исправлен.', reply_markup=keyboard)
                elif result == TimeoutError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - TimeoutError!\n - отправить конфиг деплоя не удалось ...',
                                          reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет такого условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except AttributeError:
                result = thread.result
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - AttributeError:\n{result}\n - отправить конфиг деплоя не удалось ...',
                                      reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception: \n{e.with_traceback()}', reply_markup=keyboard)

    # исправить путь деплоя и сервер
    elif 'deploy_path' in call.data:
        ip = call.data.split()[1]
        reg_num = call.data.split()[2]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{call.message.text}\n\n - подключаюсь к {ip} ...')

        command = f"""rm -rf /opt/local_repo; echo 'local_repo_path = "/mnt/data/local_repo";\ndeploy_server_port = "8181";\nrunning_software_path = "/mnt/data/bin";\nremote_repo_address = "http://10.100.128.1:8080";\nmqtt_agent_address = "http://127.0.0.1:9194";\ndeploy_policy = "sspti";\nsqlite_path = "/mnt/data/root/mqtt_agent/data.db3";\nmqtt_host = "localhost:1883";' > /etc/deploy-server/config; systemctl restart deploy_server"""
        threadname = f'deploy_path_send {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            result = thread.result

            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг деплоя исправлен.', reply_markup=keyboard)
            elif result == TimeoutError:
                print('\n - deploy send ', ip, reg_num, '- TimeoutError\n')
                print(' - повтор подключения к ', ip, '...')
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повтор подключения к ...')
                thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                          args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
                thread.start()
                thread.join()

                try:
                    result = thread.result
                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг деплоя исправлен.', reply_markup=keyboard)
                    elif result == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - отправить конфиг деплоя не удалось ...',
                                              reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет такого условия!\n\nresult:\n{result}', reply_markup=keyboard)
                except AttributeError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - AttributeError:\n{result}\n - отправить конфиг деплоя не удалось ...',
                                          reply_markup=keyboard)
            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет такого условия!\n\n - result:\n{result}', reply_markup=keyboard)
        except AttributeError:
            print(' - повтор подключения к ', ip, '...')
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повтор подключения к ...')
            thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
            thread.start()
            thread.join()

            try:
                result = thread.result
                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг деплоя исправлен.', reply_markup=keyboard)
                elif result == TimeoutError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - TimeoutError!\n - отправить конфиг деплоя не удалось ...',
                                          reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет такого условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except AttributeError:
                result = thread.result
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - AttributeError:\n{result}\n - отправить конфиг деплоя не удалось ...',
                                      reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception: \n{e.with_traceback()}', reply_markup=keyboard)

    # исправить деплой + таг пак
    elif 'd_t_c' in call.data:
        input_data = call.data.split()
        ip = input_data[1]
        reg_num = input_data[2]
        dev_id = input_data[3]
        dev_id_pass = input_data[4]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
        command = f"""echo 'local_repo_path = "/mnt/data/local_repo";\ndeploy_server_port = "8181";\nrunning_software_path = "/mnt/data/bin";\nremote_repo_address = "http://10.100.128.1:8080";\nmqtt_agent_address = "http://127.0.0.1:9194";\ndeploy_policy = "sspti";\nsqlite_path = "/mnt/data/root/mqtt_agent/data.db3";\nmqtt_host = "localhost:1883";' > /etc/deploy-server/config; systemctl restart deploy_server; echo 'tag_address = \"194.226.138.63\";\ntag_port = \"48888\";\npublic_key_path = \"/opt/tagpack-server/tagpack.pem\";\nstorage_path = \"/opt/tag_storage\";\nport = \"8080\";\ntag_timeout = \"20000\";\ntag_device_number = \"{dev_id}\";\ntag_device_secret = \"{dev_id_pass}\";\narchive_mode = false;' > /etc/tagpack-server/config; systemctl restart tagpack_server"""
        threadname = f'deploy_and_tag_configs {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                  args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            result = thread.result
            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг таг пака исправлен.', reply_markup=keyboard)
            elif result == TimeoutError:

                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...')
                thread.start()
                thread.join()
                result = thread.result

                try:
                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг таг пака исправлен.', reply_markup=keyboard)
                    elif result == TimeoutError:
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
                except Exception as e:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)

            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет условия!\n\nresult:\n{result}', reply_markup=keyboard)
        except AttributeError:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повторяю попытку ...')
            thread.start()
            thread.join()
            result = thread.result

            try:
                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг таг пака исправлен.', reply_markup=keyboard)
                elif result == TimeoutError:
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except Exception as e:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)

    # исправить пути деплоя + таг пак
    elif 'd_t_p' in call.data:
        input_data = call.data.split()
        ip = input_data[1]
        reg_num = input_data[2]
        dev_id = input_data[3]
        dev_id_pass = input_data[4]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
        command = f"""rm -rf /opt/local_repo; echo 'local_repo_path = "/mnt/data/local_repo";\ndeploy_server_port = "8181";\nrunning_software_path = "/mnt/data/bin";\nremote_repo_address = "http://10.100.128.1:8080";\nmqtt_agent_address = "http://127.0.0.1:9194";\ndeploy_policy = "sspti";\nsqlite_path = "/mnt/data/root/mqtt_agent/data.db3";\nmqtt_host = "localhost:1883";' > /etc/deploy-server/config; systemctl restart deploy_server; echo 'tag_address = \"194.226.138.63\";\ntag_port = \"48888\";\npublic_key_path = \"/opt/tagpack-server/tagpack.pem\";\nstorage_path = \"/opt/tag_storage\";\nport = \"8080\";\ntag_timeout = \"20000\";\ntag_device_number = \"{dev_id}\";\ntag_device_secret = \"{dev_id_pass}\";\narchive_mode = false;' > /etc/tagpack-server/config; systemctl restart tagpack_server"""
        threadname = f'deploy_and_tag_configs {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                  args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            result = thread.result
            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг таг пака исправлен.', reply_markup=keyboard)
            elif result == TimeoutError:

                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...')
                thread.start()
                thread.join()

                try:
                    result = thread.result
                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг таг пака исправлен.', reply_markup=keyboard)
                    elif result == TimeoutError:
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
                except Exception as e:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)

            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
        except AttributeError:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повторяю попытку ...')
            thread.start()
            thread.join()
            result = thread.result

            try:
                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг таг пака исправлен.', reply_markup=keyboard)
                elif result == TimeoutError:
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except Exception as e:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)

    # исправить деплой + бродкаст
    elif 'd_and_b_conf' in call.data:
        input_data = call.data.split()
        ip = input_data[1]
        reg_num = input_data[2]
        broadcast_ip = input_data[3]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
        command = f"""echo 'local_repo_path = "/mnt/data/local_repo";\ndeploy_server_port = "8181";\nrunning_software_path = "/mnt/data/bin";\nremote_repo_address = "http://10.100.128.1:8080";\nmqtt_agent_address = "http://127.0.0.1:9194";\ndeploy_policy = "sspti";\nsqlite_path = "/mnt/data/root/mqtt_agent/data.db3";\nmqtt_host = "localhost:1883";' > /etc/deploy-server/config; systemctl restart deploy_server; echo 'auto eth0\niface eth0 inet static\n  address {broadcast_ip}\n  netmask 255.255.248.0' > /etc/network/interfaces.d/broadcast_interface;systemctl restart broadcast_server;systemctl restart broadcast_client"""
        threadname = f'deploy_broadcast_send {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                  args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            result = thread.result
            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг бродкаста исправлен.', reply_markup=keyboard)
            elif result == TimeoutError:
                print(' - timeout error')
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...')
                thread.start()
                thread.join()

                try:
                    result = thread.result
                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг бродкаста исправлен.', reply_markup=keyboard)
                    elif result == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
                except Exception:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - Exception!\n - данные не отправлены ...', reply_markup=keyboard)
            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
        except AttributeError:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повторяю попытку ...')
            thread.start()
            thread.join()

            try:
                result = thread.result
                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг бродкаста исправлен.', reply_markup=keyboard)
                elif result == TimeoutError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - AttributeError:\n{result}\n - данные не отправлены ...', reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except Exception:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - Exception!\n - данные не отправлены ...', reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)

    # исправить пути деплоя + бродкаст
    elif 'p_and_b_conf' in call.data:
        input_data = call.data.split()
        ip = input_data[1]
        reg_num = input_data[2]
        broadcast_ip = input_data[3]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
        command = f"""rm -rf /opt/local_repo; echo 'local_repo_path = "/mnt/data/local_repo";\ndeploy_server_port = "8181";\nrunning_software_path = "/mnt/data/bin";\nremote_repo_address = "http://10.100.128.1:8080";\nmqtt_agent_address = "http://127.0.0.1:9194";\ndeploy_policy = "sspti";\nsqlite_path = "/mnt/data/root/mqtt_agent/data.db3";\nmqtt_host = "localhost:1883";' > /etc/deploy-server/config; systemctl restart deploy_server; echo 'auto eth0\niface eth0 inet static\n  address {broadcast_ip}\n  netmask 255.255.248.0' > /etc/network/interfaces.d/broadcast_interface;systemctl restart broadcast_server;systemctl restart broadcast_client"""
        threadname = f'deploy_broad_send {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                  args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            result = thread.result
            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг бродкаста исправлен.', reply_markup=keyboard)
            elif result == TimeoutError:
                print(' - timeout error')
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...')
                thread.start()
                thread.join()

                try:
                    result = thread.result
                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг бродкаста исправлен.', reply_markup=keyboard)
                    elif result == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
                except Exception:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - Exception!\n - данные не отправлены ...', reply_markup=keyboard)
            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
        except AttributeError:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повторяю попытку ...')
            thread.start()
            thread.join()

            try:
                result = thread.result
                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг деплоя исправлен.\n - конфиг бродкаста исправлен.', reply_markup=keyboard)
                elif result == TimeoutError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - AttributeError:\n{result}\n - данные не отправлены ...', reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except Exception:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - Exception!\n - данные не отправлены ...', reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)

    # исправить бродкаст + таг пак + деплой
    elif 's_all' in call.data:
        input_data = call.data.split()
        # print(' - input data: ', input_data)
        ip = input_data[1]
        reg_num = input_data[2]
        broadcast_ip = input_data[3]
        short_sn = input_data[4]
        # print(' - short_sn: ', short_sn)

        # dev_id = input_data[4]
        # dev_id_pass = input_data[5]

        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        # дергаем заново тагпак, т.к. в кнопках, нельзя передавать такую длину сообщения, пришлось укоротить и пересоздать.
        def create_tagpack():
            spreadsheet_id = config.tagpack_spreadsheet_id
            range_var = 'B2:E1000'
            major = 'ROWS'
            sheet = google_sheets_read(spreadsheet_id, range_var, major)

            for row in sheet:
                if short_sn in row:
                    # print(row)
                    dev_id = row[1]
                    dev_id_pass = row[2]
                    # print('таг пак выполнился: ', dev_id, dev_id_pass)
                    return dev_id, dev_id_pass
                else:
                    pass

        dev_id_and_pass_tagpack = create_tagpack()
        # print(dev_id_and_pass_tagpack)
        dev_id = dev_id_and_pass_tagpack[0]
        dev_id_pass = dev_id_and_pass_tagpack[1]
        # print(' - dev_id: ', dev_id)
        # print(' - pass: ', dev_id_pass)

        command = f"""echo 'local_repo_path = "/mnt/data/local_repo";\ndeploy_server_port = "8181";\nrunning_software_path = "/mnt/data/bin";\nremote_repo_address = "http://10.100.128.1:8080";\nmqtt_agent_address = "http://127.0.0.1:9194";\ndeploy_policy = "sspti";\nsqlite_path = "/mnt/data/root/mqtt_agent/data.db3";\nmqtt_host = "localhost:1883";' > /etc/deploy-server/config; systemctl restart deploy_server; echo 'auto eth0\niface eth0 inet static\n  address {broadcast_ip}\n  netmask 255.255.248.0' > /etc/network/interfaces.d/broadcast_interface;systemctl restart broadcast_server;systemctl restart broadcast_client; echo 'tag_address = \"194.226.138.63\";\ntag_port = \"48888\";\npublic_key_path = \"/opt/tagpack-server/tagpack.pem\";\nstorage_path = \"/opt/tag_storage\";\nport = \"8080\";\ntag_timeout = \"20000\";\ntag_device_number = \"{dev_id}\";\ntag_device_secret = \"{dev_id_pass}\";\narchive_mode = false;' > /etc/tagpack-server/config; systemctl restart tagpack_server"""
        threadname = f'all_configs_send {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            result = thread.result
            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг бродкаста исправлен. \n - конфиг таг пака исправлен. \n - конфиг деплоя исправлен.\n',
                                      reply_markup=keyboard)
            elif result == TimeoutError:
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...')
                thread.start()
                thread.join()
                try:
                    result = thread.result
                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг бродкаста исправлен. \n - конфиг таг пака исправлен. \n - конфиг деплоя исправлен.\n',
                                              reply_markup=keyboard)
                    elif result == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
                except Exception as e:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - Exception:\n{e.with_traceback()}\n - данные не отправлены ...',
                                          reply_markup=keyboard)

            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет условия!\n\nresult:\n{result}', reply_markup=keyboard)

        except AttributeError:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повторяю попытку ...')
            thread.start()
            thread.join()
            try:
                result = thread.result
                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг бродкаста исправлен. \n - конфиг таг пака исправлен. \n - конфиг деплоя исправлен.\n',
                                          reply_markup=keyboard)
                elif result == TimeoutError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except Exception as e:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - Exception:\n{e.with_traceback()}\n - данные не отправлены ...',
                                      reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{e.with_traceback()}\n - данные не отправлены ...',
                                  reply_markup=keyboard)

    # исправить бродкаст + таг пак + путь деплоя
    elif 'sp_all' in call.data:
        input_data = call.data.split()
        ip = input_data[1]
        reg_num = input_data[2]
        broadcast_ip = input_data[3]
        short_sn = input_data[4]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        # дергаем заново тагпак, т.к. в кнопках, нельзя передавать такую длину сообщения, пришлось укоротить и пересоздать.
        def create_tagpack():
            spreadsheet_id = config.tagpack_spreadsheet_id
            range_var = 'B2:E1000'
            major = 'ROWS'
            sheet = google_sheets_read(spreadsheet_id, range_var, major)

            for row in sheet:
                if short_sn in row:
                    # print(row)
                    dev_id = row[1]
                    dev_id_pass = row[2]
                    # print('таг пак выполнился: ', dev_id, dev_id_pass)
                    return dev_id, dev_id_pass
                else:
                    pass

        dev_id_and_pass_tagpack = create_tagpack()
        dev_id = dev_id_and_pass_tagpack[0]
        dev_id_pass = dev_id_and_pass_tagpack[1]

        command = f"""rm -rf /opt/local_repo; echo 'local_repo_path = "/mnt/data/local_repo";\ndeploy_server_port = "8181";\nrunning_software_path = "/mnt/data/bin";\nremote_repo_address = "http://10.100.128.1:8080";\nmqtt_agent_address = "http://127.0.0.1:9194";\ndeploy_policy = "sspti";\nsqlite_path = "/mnt/data/root/mqtt_agent/data.db3";\nmqtt_host = "localhost:1883";' > /etc/deploy-server/config; systemctl restart deploy_server; echo 'auto eth0\niface eth0 inet static\n  address {broadcast_ip}\n  netmask 255.255.248.0' > /etc/network/interfaces.d/broadcast_interface;systemctl restart broadcast_server;systemctl restart broadcast_client; echo 'tag_address = \"194.226.138.63\";\ntag_port = \"48888\";\npublic_key_path = \"/opt/tagpack-server/tagpack.pem\";\nstorage_path = \"/opt/tag_storage\";\nport = \"8080\";\ntag_timeout = \"20000\";\ntag_device_number = \"{dev_id}\";\ntag_device_secret = \"{dev_id_pass}\";\narchive_mode = false;' > /etc/tagpack-server/config; systemctl restart tagpack_server"""
        threadname = f'all_configs_send {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            result = thread.result
            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг бродкаста исправлен. \n - конфиг таг пака исправлен. \n - конфиг деплоя исправлен.\n',
                                      reply_markup=keyboard)
            elif result == TimeoutError:
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...')
                thread.start()
                thread.join()
                try:
                    result = thread.result
                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг бродкаста исправлен. \n - конфиг таг пака исправлен. \n - конфиг деплоя исправлен.\n',
                                              reply_markup=keyboard)
                    elif result == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
                except Exception as e:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - Exception:\n{e.with_traceback()}\n - данные не отправлены ...',
                                          reply_markup=keyboard)

            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет условия!\n\nresult:\n{result}', reply_markup=keyboard)
        except AttributeError:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повторяю попытку ...')
            thread.start()
            thread.join()
            try:
                result = thread.result
                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг бродкаста исправлен. \n - конфиг таг пака исправлен. \n - конфиг деплоя исправлен.\n',
                                          reply_markup=keyboard)
                elif result == TimeoutError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - TimeoutError!\n - данные не отправлены ...', reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except Exception as e:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - Exception:\n{e.with_traceback()}\n - данные не отправлены ...',
                                      reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{e.with_traceback()}\n - данные не отправлены ...',
                                  reply_markup=keyboard)

    # исправить бродкаст + таг пак
    elif 'broad_tag_conf' in call.data:
        input_data = call.data.split()
        ip = input_data[1]
        reg_num = input_data[2]
        broadcast_ip = input_data[3]
        short_sn = input_data[4]
        print(' - short_sn: ', short_sn)

        # dev_id = input_data[4]
        # dev_id_pass = input_data[5]

        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        # дергаем заново тагпак, т.к. в кнопках, нельзя передавать такую длину сообщения, пришлось укоротить и пересоздать.
        def create_tagpack():
            spreadsheet_id = config.tagpack_spreadsheet_id
            range_var = 'B2:E1000'
            major = 'ROWS'
            sheet = google_sheets_read(spreadsheet_id, range_var, major)

            for row in sheet:
                if short_sn in row:
                    # print(row)
                    dev_id = row[1]
                    dev_id_pass = row[2]
                    # print('таг пак выполнился: ', dev_id, dev_id_pass)
                    return dev_id, dev_id_pass
                else:
                    pass

        dev_id_and_pass_tagpack = create_tagpack()
        print(dev_id_and_pass_tagpack)
        dev_id = dev_id_and_pass_tagpack[0]
        dev_id_pass = dev_id_and_pass_tagpack[1]
        print(' - dev_id: ', dev_id)
        print(' - pass: ', dev_id_pass)

        command = f"""echo 'auto eth0\niface eth0 inet static\n  address {broadcast_ip}\n  netmask 255.255.248.0' > /etc/network/interfaces.d/broadcast_interface;systemctl restart broadcast_server;systemctl restart broadcast_client; echo 'tag_address = \"194.226.138.63\";\ntag_port = \"48888\";\npublic_key_path = \"/opt/tagpack-server/tagpack.pem\";\nstorage_path = \"/opt/tag_storage\";\nport = \"8080\";\ntag_timeout = \"20000\";\ntag_device_number = \"{dev_id}\";\ntag_device_secret = \"{dev_id_pass}\";\narchive_mode = false;' > /etc/tagpack-server/config; systemctl restart tagpack_server"""
        threadname = f'broadcast_tag_send {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            result = thread.result
            if result == []:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - конфиг бродкаста исправлен. \n - конфиг таг пака исправлен.\n',
                                      reply_markup=keyboard)
            elif result == TimeoutError:
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...')
                thread.start()
                thread.join()

                try:
                    result = thread.result
                    if result == []:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - конфиг бродкаста исправлен. \n - конфиг таг пака исправлен.\n',
                                              reply_markup=keyboard)
                    elif result == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - данные не отправлены ...',
                                              reply_markup=keyboard)
                    else:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
                except Exception as e:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - Exception:\n{e.with_traceback()}\n - данные не отправлены ...',
                                          reply_markup=keyboard)
            else:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - нет условия!\n\nresult:\n{result}', reply_markup=keyboard)

        except AttributeError:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError!\n - повторяю попытку ...')
            thread.start()
            thread.join()

            try:
                result = thread.result
                if result == []:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - конфиг бродкаста исправлен. \n - конфиг таг пака исправлен.\n',
                                          reply_markup=keyboard)
                elif result == TimeoutError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError!\n - TimeoutError!\n - данные не отправлены ...',
                                          reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - нет условия!\n\n - result:\n{result}', reply_markup=keyboard)
            except Exception as e:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - Exception:\n{e.with_traceback()}\n - данные не отправлены ...',
                                      reply_markup=keyboard)

        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{e.with_traceback()}\n - данные не отправлены ...',
                                  reply_markup=keyboard)

    # исправить впн
    elif 'fix_vpn' in call.data:
        input_tg = call.data.split()
        print(' - input_tg:', input_tg)
        ip = input_tg[1]
        reg_num = input_tg[2]
        dev_id = input_tg[3]

        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        try:
            if dev_id != 'NONE':
                def sftp_download():
                    try:
                        transport = paramiko.Transport((config.server_ip, 22))
                        transport.connect(None, config.server_username, config.server_password)
                        print(' - connect ', config.server_ip)
                        print(' - transport.name: ', transport.name)
                        sftp = paramiko.SFTPClient.from_transport(transport)
                        filepath_issued = f"/root/configs_monitoring/easyrsa3/pki/issued/{dev_id}.crt"
                        filepath_private = f"/root/configs_monitoring/easyrsa3/pki/private/{dev_id}.key"
                        localpath_issued = f"{config.temp_dir}{dev_id}.crt"
                        localpath_private = f"{config.temp_dir}{dev_id}.key"
                        sftp.get(filepath_issued, localpath_issued)
                        sftp.get(filepath_private, localpath_private)
                        print(' - download!')

                        sftp.close()
                        print(' - sftp download close')
                        transport.close()
                        print(" - sftp transport download close")
                        print(' - transport.name: ', transport.name)
                        print(' - return True')
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - сертификат и ключ найдены.\n - занимаюсь {ip} ...')

                        return True

                    except FileNotFoundError:
                        print(' - сертификат или ключ - не найдены.')
                        sftp.close()
                        transport.close()

                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n - для {dev_id} нету файлов ... \n - создаю ...')

                        # функция создания впн сертификата
                        print(' - функция создания впн сертификата')
                        command = f'cd /root/configs_monitoring/easyrsa3/; export EASYRSA_PASSIN=pass:0064789; ./easyrsa build-client-full {dev_id} nopass'
                        threadname = f'create_vpn {dev_id} | {call.message.chat.username}'
                        thread_create_vpn = ThreadWithResult(target=ssh_connect, name=threadname,
                                                             args=[config.server_ip, config.server_username, config.server_password, command, 60, 60])
                        thread_create_vpn.start()
                        thread_create_vpn.join()

                        print()
                        print(' - result: ', thread_create_vpn.result)
                        print()

                        # повторить загрузку файла
                        try:
                            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                  text=f'{call.message.text}\n - для {dev_id} нету файлов ... \n - создаю ... \n - занимаюсь {ip} ... ')
                            transport = paramiko.Transport((config.server_ip, 22))
                            transport.connect(None, config.server_username, config.server_password)
                            print(' - connect ', config.server_ip)
                            sftp = paramiko.SFTPClient.from_transport(transport)
                            filepath_issued = f"/root/configs_monitoring/easyrsa3/pki/issued/{dev_id}.crt"
                            filepath_private = f"/root/configs_monitoring/easyrsa3/pki/private/{dev_id}.key"
                            localpath_issued = f"{config.temp_dir}{dev_id}.crt"
                            localpath_private = f"{config.temp_dir}{dev_id}.key"
                            sftp.get(filepath_issued, localpath_issued)
                            sftp.get(filepath_private, localpath_private)
                            print(' - download!')
                            sftp.close()
                            print(' - sftp download close')
                            transport.close()
                            print(" - sftp transport download close")
                            print(' - transport.name: ', transport.name)
                            print(' - return True')
                            return True

                        except FileNotFoundError:
                            print(' - сертификат или ключ - не найдены.')
                            print(' - создать не удалось')
                            # bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{call.message.text}\n - для {dev_id} нету файлов ... \n - создаю ... \n - не удалось создать сертификат\ключ.')
                            sftp.close()
                            transport.close()
                            return None

                    except TimeoutError:
                        print('Timeuout error connect ', config.server_ip)
                        print('проверь впн')
                        sftp.close()
                        transport.close()
                        return TimeoutError

                def sftp_upload():

                    transport = paramiko.Transport((ip, 22))
                    transport.connect(None, config.wirenboard_username, config.wirenboard_password)
                    print(' - upload - start ...')
                    print(' - connect ', ip)
                    print('-', transport.name, '- start')

                    try:
                        sftp = paramiko.SFTPClient.from_transport(transport)
                        print(' - sftp upload: ', sftp)


                        localpath_issued = f"{config.temp_dir}{dev_id}.crt"
                        localpath_private = f"{config.temp_dir}{dev_id}.key"
                        filepath_issued = f"/etc/openvpn/client/{dev_id}.crt"
                        filepath_private = f"/etc/openvpn/client/{dev_id}.key"
                        sftp.put(localpath_issued, filepath_issued)
                        sftp.put(localpath_private, filepath_private)
                        print(' - upload!')
                        sftp.close()
                        print(' - ', transport.name, ' - sftp.close')
                        transport.close()
                        print(' - ', transport.name, ' - transport.close')
                        print(' - return True')
                        return True

                    except FileNotFoundError:
                        print('сертификат или ключ - не найдены.')
                        print('почему-то не создались ... см. функцию sftp_download')
                        if sftp: sftp.close()
                        if transport: transport.close()
                        return FileNotFoundError
                    # except TimeoutError:
                    #     print('Timeout error connect ', ip)
                    #     if sftp: sftp.close()
                    #     if transport: transport.close()
                    #     return TimeoutError
                    except paramiko.sftp.SFTPError as e_p:
                        # if sftp: sftp.close()
                        # if transport: transport.close()
                        print('\n - paramiko.sftp.SFTPError: ', e_p.with_traceback(), '\n')
                        return False
                    except Exception as ex:
                        print(' - ваще, Exception: ', ex.with_traceback(), '\n')
                        # sftp.close()
                        # transport.close()
                        return False

                threadname = f'sftp_download {ip} | {dev_id} | {call.message.chat.username}'
                thread_download = ThreadWithResult(target=sftp_download, name=threadname, args=[])
                thread_download.start()
                thread_download.join()

                if thread_download.result == True:
                    print(' - sftp_download result: ', thread_download.result)
                    threadname = f'sftp_upload {ip} | {dev_id} | {call.message.chat.username}'
                    thread_upload = ThreadWithResult(target=sftp_upload, name=threadname, args=[])
                    thread_upload.start()
                    thread_upload.join()

                    try:
                        result_upload = thread_upload.result
                        if result_upload == True:
                            command = f"""echo 'client\ndev tun\nproto udp\nremote 194.226.138.63 20102\nresolv-retry infinite\nnobind\nuser nobody\ngroup nogroup\nca /etc/openvpn/client/ca.crt\ncert /etc/openvpn/client/{dev_id}.crt\nkey /etc/openvpn/client/{dev_id}.key\ncipher AES-256-CBC\nverb 3\n;mute 20' > /etc/openvpn/client/client_static_rusagro.conf;echo 'client\ndev tun\nproto udp\nremote 81.200.119.153 1196\nresolv-retry infinite\nnobind\nuser nobody\ngroup nogroup\nca /etc/openvpn/client/ca.crt\ncert /etc/openvpn/client/{dev_id}.crt\nkey /etc/openvpn/client/{dev_id}.key\ncipher AES-256-CBC\nverb 3\n;mute 20' > /etc/openvpn/client/client_static.conf;systemctl restart openvpn-client@client_static_rusagro;systemctl restart openvpn-client@client_static"""
                            threadname = f'fix_vpn {ip} | {dev_id} | {call.message.chat.username}'
                            thread_ssh = ThreadWithResult(target=ssh_connect, name=threadname,
                                                          args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
                            thread_ssh.start()
                            thread_ssh.join()

                            try:
                                result_ssh_fix = thread_ssh.result

                                if result_ssh_fix == []:
                                    print(' - fix_vpn - ok!')
                                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                          text=f'{call.message.text}\n\n - vpn`ы исправлены.', reply_markup=keyboard)
                                elif result_ssh_fix == TimeoutError or result_ssh_fix == AttributeError:
                                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                          text=f'{call.message.text}\n\n - TimeoutError\n - AttributeError\n\n - result:\n{traceback.format_exc()}\n\n - повторяю попытку ...',
                                                          reply_markup=keyboard)
                                    thread_ssh.start()
                                    thread_ssh.join()
                                    result_ssh_fix = thread_ssh.result
                                    if result_ssh_fix == []:
                                        print(' - fix_vpn - ok!')
                                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                              text=f'{call.message.text}\n\n - vpn`ы исправлены.', reply_markup=keyboard)
                                    elif result_ssh_fix == TimeoutError or result_ssh_fix == AttributeError:
                                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                              text=f'{call.message.text}\n\n - TimeoutError\n - AttributeError\n\n - result:\n{traceback.format_exc()}\n\n - конфиг не создан.\n',
                                                              reply_markup=keyboard)
                                    else:
                                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                              text=f'{call.message.text}\n - нет условия!\n - но файлы скачаны)\n - лежат тут:\n{config.temp_dir}\n\n - result:\n{traceback.format_exc()}',
                                                              reply_markup=keyboard)
                            except paramiko.sftp.SFTPError:
                                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                          text=f'{call.message.text}\n\n - файлы загружены.\n - во время отправки конфигов, вернулся ответ, которого быть не должно.\n - пишу данное исключение для тачки, с забитой памятью. скрипт отработал, службы не поднимаются, т.к. забита память.\n\n - ssh result:\n{result_ssh_fix}', reply_markup=keyboard)
                        elif result_upload == FileNotFoundError:
                            print(' - upload = None ... ')
                            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                  text=f'{call.message.text}\n - нету файлов в temp, почему-то не сработало создание\загрузка ...',
                                                  reply_markup=keyboard)
                        elif result_upload == TimeoutError or result_upload == AttributeError or result_upload == False:
                            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                  text=f'{call.message.text}\n - TimeoutError or AttributeError при сфтп загрузке файлов ...\n - повторяю операцию ...')
                            thread_upload.start()
                            thread_upload.join()
                            result_upload = thread_upload.result

                            if result_upload == True:
                                command = f"""echo 'client\ndev tun\nproto udp\nremote 194.226.138.63 20102\nresolv-retry infinite\nnobind\nuser nobody\ngroup nogroup\nca /etc/openvpn/client/ca.crt\ncert /etc/openvpn/client/{dev_id}.crt\nkey /etc/openvpn/client/{dev_id}.key\ncipher AES-256-CBC\nverb 3\n;mute 20' > /etc/openvpn/client/client_static_rusagro.conf;echo 'client\ndev tun\nproto udp\nremote 81.200.119.153 1196\nresolv-retry infinite\nnobind\nuser nobody\ngroup nogroup\nca /etc/openvpn/client/ca.crt\ncert /etc/openvpn/client/{dev_id}.crt\nkey /etc/openvpn/client/{dev_id}.key\ncipher AES-256-CBC\nverb 3\n;mute 20' > /etc/openvpn/client/client_static.conf;systemctl restart openvpn-client@client_static_rusagro;systemctl restart openvpn-client@client_static"""
                                threadname = f'fix_vpn {ip} | {dev_id} | {call.message.chat.username}'
                                thread_ssh = ThreadWithResult(target=ssh_connect, name=threadname,
                                                              args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
                                thread_ssh.start()
                                thread_ssh.join()

                                result_ssh_fix = thread_ssh.result

                                if result_ssh_fix == []:
                                    print(' - fix_vpn - ok!')
                                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                          text=f'{call.message.text}\n\n - vpn`ы исправлены.', reply_markup=keyboard)
                                elif result_ssh_fix == FileNotFoundError or result_ssh_fix == TimeoutError or result_ssh_fix == AttributeError:
                                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                          text=f'{call.message.text}\n\n - FileNotFoundError\n - TimeoutError\n - AttributeError\n\n - result:\n{traceback.format_exc()}\n\n - повторяю попытку ...',
                                                          reply_markup=keyboard)
                                    thread_ssh.start()
                                    thread_ssh.join()
                                    result_ssh_fix = thread_ssh.result
                                    if result_ssh_fix == []:
                                        print(' - fix_vpn - ok!')
                                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                              text=f'{call.message.text}\n\n - vpn`ы исправлены.', reply_markup=keyboard)
                                    elif result_ssh_fix == FileNotFoundError or result_ssh_fix == TimeoutError or result_ssh_fix == AttributeError:
                                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                              text=f'{call.message.text}\n\n - FileNotFoundError\n - TimeoutError\n - AttributeError\n\n - result:\n{traceback.format_exc()}\n\n - конфиг не создан.\n',
                                                              reply_markup=keyboard)
                                    else:
                                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                              text=f'{call.message.text}\n - нет условия!\n\n - result:\n{traceback.format_exc()}',
                                                              reply_markup=keyboard)

                            elif result_upload == TimeoutError or result_upload == AttributeError:
                                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                      text=f'{call.message.text}\n - TimeoutError or AttributeError\n - TimeoutError or AttributeError\n - загрузка не удалась ...',
                                                      reply_markup=keyboard)

                            else:
                                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                                      text=f'{call.message.text}\n - TimeoutError or AttributeError\n - нет условия!',
                                                      reply_markup=keyboard)



                    except AttributeError:

                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n - не удалось загрузить файлы.', reply_markup=keyboard)

                elif thread_download.result == FileNotFoundError or thread_download.result == TimeoutError or thread_download.result == AttributeError:
                    print(' - download = None ...')
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n - для {dev_id} нету файлов ... \n - создать не получилось ...\n - FileNotFoundError\n - TimeoutError\n - AttributeError\n\n - result:\n{traceback.format_exc()}',
                                          reply_markup=keyboard)

                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n - нет условия!\n\n - result:\n{traceback.format_exc()}',
                                          reply_markup=keyboard)
            elif dev_id == 'NONE':
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n - wifi mac - не загрузился!\n - не из чего делать создавать dev_id.',
                                      reply_markup=keyboard)

        except Exception:
            print(traceback.format_exc())
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - ошибка Exception:\n{traceback.format_exc()}',
                                  reply_markup=keyboard)

    # о справочниках
    elif 'tag_storage' in call.data:
        print(' - о справочниках', '|', 'call.data: ', call.data.split(), '|', call.message.chat.username)
        ip_stend = '192.168.0.97'
        input_data = call.data.split()
        ip = input_data[1]
        reg_num = input_data[2]
        dev_id = input_data[3]

        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        # подключаемся по ссш к стенду
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{call.message.text}\n\n - подключаюсь к {ip_stend} ...')

        command = f'cat /opt/tag_storage/TAG_MODEL_SRI_AGRI_MACH | grep -A5 -B5 {dev_id}; cat /opt/tag_storage/TAG_MODEL_SRI_DEVICE | grep -A5 -B1 {dev_id}'
        threadname = f'tag_storage {input_data} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                  args=[ip_stend, config.wirenboard_username, config.wirenboard_password, command, 10, 10])
        thread.start()
        thread.join()

        # получаем ответ, выводим в тг
        try:
            all_data_result = thread.result
            print('\n--- all_data_result: ', all_data_result, '\n')

            if all_data_result == TimeoutError:
                print('\n --- TimeoutError --- ', ip_stend, ' - недоступен\n')
                # подключаемся по ссш к второму стенду

                ip_stend = '192.168.0.46'
                print(' --- подключаюсь ко второму: ', ip_stend)
                input_data = call.data.split()
                ip = input_data[1]
                reg_num = input_data[2]
                dev_id = input_data[3]

                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - стенд 192.168.0.97 - недоступен.\n - подключаюсь к {ip_stend} ...')

                command = f'cat /opt/tag_storage/TAG_MODEL_SRI_AGRI_MACH | grep -A5 -B5 {dev_id}; cat /opt/tag_storage/TAG_MODEL_SRI_DEVICE | grep -A5 -B1 {dev_id}'
                threadname = f'tag_storage {input_data} | {call.message.chat.username}'
                thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip_stend, config.wirenboard_username, config.wirenboard_password, command, 10, 10])
                thread.start()
                thread.join()

                try:
                    all_data_result = thread.result

                    if all_data_result == TimeoutError:
                        print('\n --- TimeoutError --- ', ip_stend, ' - недоступен\n')
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - стенд 192.168.0.97 - недоступен.\n - стенд 192.168.0.46 - недоступен.\n - данных не будет.', reply_markup=keyboard)
                    else:
                        all_data = []
                        for line in all_data_result:
                            clear_line = line.replace(',', '')
                            clear_line = str(clear_line.strip())
                            clear_line = str(clear_line.replace('"', ''))
                            all_data.append(f'{clear_line}\n')

                        all_data = ''.join(all_data)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\n - взято из {ip_stend}:\n{all_data}', reply_markup=keyboard)
                except AttributeError as eat:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - AttributeError! - AttributeError:\n{eat.with_traceback()}\n\n - данных не будет.',
                                          reply_markup=keyboard)

            else:
                all_data = []
                for line in all_data_result:
                    clear_line = line.replace(',', '')
                    clear_line = str(clear_line.strip())
                    clear_line = str(clear_line.replace('"', ''))
                    # print('- line: ', clear_line)
                    all_data.append(f'{clear_line}\n')

                all_data = ''.join(all_data)
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - взято из {ip_stend}:\n{all_data}', reply_markup=keyboard)

        except AttributeError as eat:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - AttributeError:\n{eat.with_traceback()}\n\n - данных не будет.', reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{e.with_traceback()}\n\n - данных не будет.', reply_markup=keyboard)

    # todo проверка конфигов (таг пак, деплой, бродкаст)
    elif 'check_configs_read' in call.data:
        print(' - check_configs_read: ', call.data.split())
        input_data = call.data.split()
        ip = input_data[1]
        reg_num = input_data[2]
        short_sn = input_data[3]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        keyboard = types.InlineKeyboardMarkup()

        def function_broadcast_config_create():
            spreadsheet_id = config.broadcast_spreadsheet_id
            major = 'ROWS'
            range_belgorod = 'Белгород!A2:D255'  # 'Sheet2!A2:E10'
            sheet_broadcats_belgorog = google_sheets_read(spreadsheet_id, range_belgorod, major)
            range_kursk = 'Курск!A2:D255'
            sheet_broadcats_kursk = google_sheets_read(spreadsheet_id, range_kursk, major)
            range_tambov = 'Тамбов!A2:D255'
            sheet_broadcats_tambov = google_sheets_read(spreadsheet_id, range_tambov, major)
            range_orel = 'Орел!A2:D255'
            sheet_broadcats_orel = google_sheets_read(spreadsheet_id, range_orel, major)
            range_primorie = 'Приморье!A2:D255'
            sheet_broadcats_primorie = google_sheets_read(spreadsheet_id, range_primorie, major)
            for row in sheet_broadcats_belgorog:
                if reg_num in row:
                    broadcast_ip = row[1]
                    print('broadcast_ip: ', broadcast_ip)
                    return broadcast_ip

            for row in sheet_broadcats_kursk:
                if reg_num in row:
                    broadcast_ip = row[1]
                    print('broadcast_ip: ', broadcast_ip)
                    return broadcast_ip

            for row in sheet_broadcats_tambov:
                if reg_num in row:
                    broadcast_ip = row[1]
                    print('broadcast_ip: ', broadcast_ip)
                    return broadcast_ip

            for row in sheet_broadcats_orel:
                if reg_num in row:
                    broadcast_ip = row[1]
                    print('broadcast_ip: ', broadcast_ip)
                    return broadcast_ip

            for row in sheet_broadcats_primorie:
                if reg_num in row:
                    broadcast_ip = row[1]
                    print('broadcast_ip: ', broadcast_ip)
                    return broadcast_ip

        def function_tackpack_config_create():

            spreadsheet_id = config.tagpack_spreadsheet_id
            range_var = 'B2:E1000'
            major = 'ROWS'
            sheet = google_sheets_read(spreadsheet_id, range_var, major)

            for row in sheet:
                if short_sn in row:
                    # print(row)
                    dev_id = row[1]
                    dev_id_pass = row[2]
                    print('таг пак выполнился: ', dev_id, dev_id_pass)
                    return dev_id, dev_id_pass
                else:
                    pass

        try:
            function_broadcast_config_create_result = function_broadcast_config_create()
            function_tackpack_config_create_result = function_tackpack_config_create()
        except TypeError:
            function_broadcast_config_create_result = None
            function_tackpack_config_create_result = None

        # подключаемся по ссш
        if function_broadcast_config_create_result == None and function_tackpack_config_create_result == None:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - бродкаст: нету в таблице!\n - тагпак: нету в таблице!\n - занимаюсь {ip} ...')
        elif function_broadcast_config_create_result == None and function_tackpack_config_create_result != None:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - бродкаст: нету в таблице!\n - тагпак: {function_tackpack_config_create_result[0]}|{function_tackpack_config_create_result[1]}\n - занимаюсь {ip} ...')
        elif function_broadcast_config_create_result != None and function_tackpack_config_create_result == None:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - бродкаст: {function_broadcast_config_create_result}\n - тагпак: нету в таблице!\n - занимаюсь {ip} ...')
        else:
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - бродкаст: {function_broadcast_config_create_result}\n - тагпак: {function_tackpack_config_create_result[0]}|{function_tackpack_config_create_result[1]}\n - занимаюсь {ip} ...')

        # command = f'cat /etc/network/interfaces.d/broadcast_interface; cat /etc/tagpack-server/config; cat /etc/deploy-server/config'
        command = f'cat /etc/network/interfaces.d/broadcast_interface; cat /etc/tagpack-server/config; cat /etc/deploy-server/config; du -b /mnt/data/etc/wb-hardware.conf; du -b /etc/wb-vehicle.conf; du -b /mnt/data/etc/wb-mqtt-serial.conf; du -b /mnt/data/etc/wb-rules/vehicle_common.js'
        threadname = f'check_configs_read {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                  args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            all_configs_data = thread.result
            print('\n - all_configs_data: ', all_configs_data, '\n')

            if all_configs_data != TimeoutError:
                try:
                    broadcast_address_from_wirenboard = str(all_configs_data[2])
                except TypeError:
                    broadcast_address_from_wirenboard = None

                if function_tackpack_config_create_result == None:
                    tag_device_number_from_table = None
                    tag_device_secret_from_table = None
                    pass

                else:
                    tag_device_number_from_table = function_tackpack_config_create_result[0]
                    tag_device_secret_from_table = function_tackpack_config_create_result[1]

                for line in all_configs_data:
                    if 'tag_address' in line:
                        tag_address_from_wirenboard = line
                        print(' - tag_adress_from_wirenboard: ', tag_address_from_wirenboard)
                    elif 'tag_device_number' in line:
                        tag_device_number_from_wirenboard = line
                        print(' - tag_device_number_from_wirenboard: ', tag_device_number_from_wirenboard)
                    elif 'tag_device_secret' in line:
                        tag_device_secret_from_wirenboard = line
                        print(' - tag_device_secret_from_wirenboard: ', tag_device_secret_from_wirenboard)
                        print(' - broadcast_address_from_wirenboard: ', broadcast_address_from_wirenboard)
                    elif 'remote_repo_address' in line:
                        remote_repo_address_from_wb = line
                        print(' - remote_repo_address_from_wb: ', remote_repo_address_from_wb)

                    elif 'local_repo_path' in line:
                        local_repo_path_from_wb = line
                        print(' - local_repo_path: ', local_repo_path_from_wb)

                    else:
                        pass

                # проверка бродкаста
                def check_broadcast():
                    if reg_num == 'None':
                        print('reg_num none')
                        return None
                    if function_broadcast_config_create_result == None:
                        print('broadcast none')
                        return None
                    if function_broadcast_config_create_result in broadcast_address_from_wirenboard:
                        print('broadcast True')
                        return True
                    elif function_broadcast_config_create_result not in broadcast_address_from_wirenboard:
                        print('broadcast False')
                        return False
                    else:
                        print('broadcast pass')
                        return False

                # проверка тагпака
                def check_tag_pack():
                    # print()
                    if function_tackpack_config_create_result == None:
                        print('tag_create: ', function_tackpack_config_create_result)
                        return None
                    #     pass
                    if tag_device_number_from_table == None or tag_device_secret_from_table == None:
                        print('tag_device_number_from_table: ', tag_device_number_from_table)
                        print('tag_device_secret_from_table: ', tag_device_secret_from_table)
                        return None
                    if tag_device_number_from_table in tag_device_number_from_wirenboard and tag_device_secret_from_table in tag_device_secret_from_wirenboard and '194.226.138.63' in tag_address_from_wirenboard:
                        print('dev_id - ok')
                        print('dev_pass - ok')
                        print('tag_address - ok')
                        return True
                    elif tag_device_number_from_table not in tag_device_number_from_wirenboard:
                        print('dev_id - don`t ok')
                        print('надо: ', tag_device_number_from_table)
                        print('установлено: ', tag_device_number_from_wirenboard)
                        return False
                    elif tag_device_secret_from_table not in tag_device_secret_from_wirenboard:
                        print('dev_pass - don`t ok')
                        return False
                    elif '194.226.138.63' not in tag_address_from_wirenboard:
                        print('tag_address - don`t ok')
                        return False
                    else:
                        print('нет условия!')

                # проверка пути деплоя
                def check_deploy_path():
                    if "/mnt/data/local_repo" in local_repo_path_from_wb:
                        print(' - local_repo_path: ', local_repo_path_from_wb)
                        return True
                    else:
                        print(' - else')
                        print(' - local_repo_path: ', local_repo_path_from_wb)
                        return False

                # проверка wb-hardware.conf
                def check_wb_hardware_conf():
                    for line in all_configs_data:
                        if '/mnt/data/etc/wb-hardware.conf' in line:
                            wb_hardware_conf_line = line
                            print(' - wb-hardware.conf line: ', wb_hardware_conf_line)
                            if 'No such file or directory' in wb_hardware_conf_line:
                                print(' - нет файла /mnt/data/etc/wb-hardware.conf')
                                return False
                            else:
                                try:
                                    wb_hardware_conf_len = int(wb_hardware_conf_line.split()[0])
                                    print(' - len wb-hardware.conf: ', wb_hardware_conf_len)
                                    if wb_hardware_conf_len > 2000:
                                        print(' - len ok!', )
                                        return True
                                    elif wb_hardware_conf_len < 2000:
                                        print(' - len - don`t ok ..., len: ', wb_hardware_conf_len)
                                        return False
                                except Exception as e:
                                    print(' - error: ', e.with_traceback())
                                    return False

                # проверка wb-vehicle.conf
                def check_wb_vehicle_conf():
                    for line in all_configs_data:
                        if '/etc/wb-vehicle.conf' in line:
                            wb_vehicle_conf_line = line
                            print(' - wb-vehicle.conf line: ', wb_vehicle_conf_line)
                            if 'No such file or directory' in wb_vehicle_conf_line:
                                print(' - нет файла /etc/wb-vehicle.conf')
                                return False
                            else:
                                try:
                                    wb_vehicle_conf_len = int(wb_vehicle_conf_line.split()[0])
                                    print(' - len wb-hardware.conf: ', wb_vehicle_conf_len)
                                    if wb_vehicle_conf_len > 500:
                                        print(' - len ok!', )
                                        return True
                                    elif wb_vehicle_conf_len < 500:
                                        print(' - len - don`t ok ..., len: ', wb_vehicle_conf_len)
                                        return False

                                except Exception as e:
                                    print(' - error: ', e.with_traceback())
                                    return False

                # проверка wb-mqtt-serial.conf
                def check_wb_mqtt_serial():
                    for line in all_configs_data:
                        if '/mnt/data/etc/wb-mqtt-serial.conf' in line:
                            wb_mqtt_serial_conf_line = line
                            print(' - wb-mqtt-serial.conf line: ', wb_mqtt_serial_conf_line)
                            if 'No such file or directory' in wb_mqtt_serial_conf_line:
                                print(' - нет файла /mnt/data/etc/wb-mqtt-serial.conf')
                                return False
                            else:
                                try:
                                    wb_mqtt_serial_conf_len = int(wb_mqtt_serial_conf_line.split()[0])
                                    print(' - len wb-hardware.conf: ', wb_mqtt_serial_conf_len)
                                    if wb_mqtt_serial_conf_len > 500:
                                        print(' - len ok!', )
                                        return True
                                    elif wb_mqtt_serial_conf_len < 500:
                                        print(' - len - don`t ok ..., len: ', wb_mqtt_serial_conf_len)
                                        return False
                                    elif wb_mqtt_serial_conf_len == 0:
                                        return False
                                except Exception as e:
                                    print(' - error: ', e.with_traceback())
                                    return False

                # проверка vehicle_common.js
                def check_vehicle_common_js():
                    for line in all_configs_data:
                        if '/mnt/data/etc/wb-rules/vehicle_common.js' in line:
                            vehicle_common_js_line = line
                            print(' - vehicle_common_js: ', vehicle_common_js_line)
                            if 'No such file or directory' in vehicle_common_js_line:
                                print(' - нет файла /mnt/data/etc/wb-rules/vehicle_common.js')
                                return False
                            else:
                                try:
                                    vehicle_common_js_len = int(vehicle_common_js_line.split()[0])
                                    print(' - len vehicle_common_js: ', vehicle_common_js_len)
                                    if vehicle_common_js_len > 19000:
                                        print(' - len ok!', )
                                        return True
                                    elif vehicle_common_js_len < 19000:
                                        print(' - len - don`t ok ..., len: ', vehicle_common_js_len)
                                        return False
                                    elif vehicle_common_js_len == 0:
                                        return False
                                except Exception as e:
                                    print(' - error: ', e.with_traceback())
                                    return False


                result_check_broadcast = check_broadcast()
                result_check_tag_pack = check_tag_pack()
                result_check_deploy_path = check_deploy_path()

                result_check_wb_hardware = check_wb_hardware_conf()
                result_check_wb_vehicle = check_wb_vehicle_conf()
                result_check_wb_mqtt_serial = check_wb_mqtt_serial()
                result_check_vehicle_common_js = check_vehicle_common_js()

                print()
                print(' - результат проверки wb_hardware: ', result_check_wb_hardware)
                print(' - результат проверки wb_vehicle: ', result_check_wb_vehicle)
                print(' - результат проверки wb_mqtt_serial: ', result_check_wb_mqtt_serial)
                print(' - результат проверки vehicle_common_js: ', result_check_vehicle_common_js)
                print()

                dev_id = tag_device_number_from_table
                dev_id_pass = tag_device_secret_from_table

                # function_ping = str('function_ping ' + ip + ' ' + reg_num)
                # sleep = str('sleep ' + ip + ' ' + reg_num)

                if function_broadcast_config_create_result != None:
                    broadcast_config_send = str('broad_send ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                    deploy_and_broadcast_configs_send = str('d_and_b_conf ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                    deploy_path_and_broadcast_configs_send = str('p_and_b_conf ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                    broadcast_and_tag_configs_send = str('broad_tag_conf ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result + ' ' + short_sn)
                    send_all_configs = str('s_all ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result + ' ' + ' ' + short_sn)
                    send_all_configs_plus_path = str('sp_all ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result + ' ' + short_sn)

                    callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст", callback_data=broadcast_config_send)
                    callback_button_send_broadcast_plus_deploy = types.InlineKeyboardButton(text="исправить бродкаст + деплой", callback_data=deploy_and_broadcast_configs_send)
                    callback_button_send_broadcast_plus_deploy_path = types.InlineKeyboardButton(text="исправить бродкаст + деплой", callback_data=deploy_path_and_broadcast_configs_send)
                    callback_button_send_all_configs = types.InlineKeyboardButton(text="исправить бродкаст + деплой + тагпак", callback_data=send_all_configs)
                    callback_button_send_all_configs_plus_path = types.InlineKeyboardButton(text="исправить бродкаст + деплой + тагпак", callback_data=send_all_configs_plus_path)
                    callback_button_broadcast_and_tag_configs = types.InlineKeyboardButton(text="исправить бродкаст + тагпак", callback_data=broadcast_and_tag_configs_send)

                if dev_id != None and dev_id_pass != None:
                    tag_pack_config_send = str('tag_send ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                    deploy_and_tag_configs_send = str('d_t_c ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                    deploy_path_and_tag_configs_send = str('d_t_p ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                    callback_button_send_tagpack = types.InlineKeyboardButton(text="исправить тагпак", callback_data=tag_pack_config_send)
                    callback_button_send_tag_plus_deploy = types.InlineKeyboardButton(text="исправить тагпак + деплой", callback_data=deploy_and_tag_configs_send)
                    callback_button_send_tag_plus_deploy_path = types.InlineKeyboardButton(text="исправить тагпак + деплой", callback_data=deploy_path_and_tag_configs_send)

                deploy_config_send = str('deploy_send ' + ip + ' ' + reg_num)
                deploy_config_send_path = str('deploy_path ' + ip + ' ' + reg_num)

                callback_button_send_deploy = types.InlineKeyboardButton(text="исправить деплой", callback_data=deploy_config_send)
                callback_button_send_deploy_path = types.InlineKeyboardButton(text="исправить деплой", callback_data=deploy_config_send_path)

                # часть 1 (бродкаст, деплой, тагпак)
                if result_check_broadcast == True \
                    and result_check_tag_pack == True \
                    and '10.100.128.1:8080' in remote_repo_address_from_wb \
                    and result_check_deploy_path == True:

                    print('бродкаст - ок!')
                    print('тагпак - ок!')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - ок!')

                    tg_check = f'broadcast - ok!\ntagpack - ok!\ndeploy - оk!'
                    tg_check_error = ''

                # путь деплоя - не ок
                elif result_check_broadcast and result_check_tag_pack == True \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:
                    print('бродкаст - ок!')
                    print('таг пак - ок!')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - не ок ...')

                    tg_check = f'broadcast - ok!\ntagpack - ok!\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)

                # сервер деплоя - не ок
                elif result_check_broadcast and result_check_tag_pack == True \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb \
                        and result_check_deploy_path == True:
                    print('бродкаст - ок!')
                    print('таг пак - ок!')
                    print('деплой - сервер - не ок')
                    print('деплой - путь - ок!')

                    tg_check = f'broadcast - ok!\ntagpack - ok!\ndeploy  - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";'
                    keyboard.add(callback_button_send_deploy)

                # сервер и путь деплоя - не ок
                elif result_check_broadcast and result_check_tag_pack == True \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:
                    print('бродкаст - ок!')
                    print('тагпак - ок!')
                    print('деплой - сервер - не ок!')
                    print('деплой - путь - не ок!')

                    tg_check = f'broadcast - ok!\ntagpack - ok!\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)

                # сервер деплоя + тагпак - не ок
                elif result_check_broadcast == True \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb \
                        and result_check_deploy_path == True:
                    print('бродкаст - ок!')
                    print('тагпак - не ок!')
                    print('деплой - сервер - не ок!')
                    print('деплой - путь - ок!')

                    tg_check = f'broadcast - ok!\ntagpack - don`t ok ... \ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";'
                    keyboard.add(callback_button_send_deploy)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_send_tag_plus_deploy)

                # тагпак + путь и сервер деплоя - не ок
                elif result_check_broadcast == True \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:
                    print('бродкаст - ок!')
                    print('тагпак - не ок!')
                    print('деплой - сервер - не ок!')
                    print('деплой - путь - не ок!')

                    tg_check = f'бродкаст - ок!\nтагпак - не ок ... \nдеплой - не ок ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'

                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_send_tag_plus_deploy_path)

                elif result_check_broadcast == True \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb \
                        and result_check_deploy_path == True:
                    print('бродкаст - ок!')
                    print('тагпак - не ок ...')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - ок!')

                    tg_check = f'broadcast - ok!\ntagpack - don`t ok ...\ndeploy - ok!'
                    tg_check_error = f'\n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";'
                    keyboard.add(callback_button_send_tagpack)

                # исправить тагпак + путь деплоя
                elif result_check_broadcast == True \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:
                    print('бродкаст - ок!')
                    print('тагпак - не ок ...')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - не ок ...')

                    tg_check = f'broadcast - ok!\ntagpack - don`t ok ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'

                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_send_tag_plus_deploy_path)


                elif result_check_broadcast == False \
                        and result_check_tag_pack == True \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:

                    print('бродкаст - не ок ...')
                    print('таг пак - ок!')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - ок!')

                    tg_check = f'broadcast - don`t ok ...\ntagpack - ok!\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";'

                    keyboard.add(callback_button_send_broadcast)
                    keyboard.add(callback_button_send_deploy)
                    keyboard.add(callback_button_send_broadcast_plus_deploy)

                # исправить бродкаст + пусть деплоя
                elif result_check_broadcast == False \
                        and result_check_tag_pack == True \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:

                    print('бродкаст - не ок ...')
                    print('таг пак - ок!')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - не ок ...')

                    tg_check = f'broadcast - don`t ok ...\ntagpack - ok!\ndeploy - don`t ok ...'
                    tg_chech_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'

                    keyboard.add(callback_button_send_broadcast)
                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_broadcast_plus_deploy_path)

                elif result_check_broadcast == False \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - не ок ...')
                    print('тагпак - не ок ...')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - ок!')

                    tg_check = f'broadcast - don`t ok ...\ntagpack - don`t ok ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";'
                    keyboard.add(callback_button_send_broadcast)
                    keyboard.add(callback_button_send_deploy)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_send_all_configs)

                # исправить бродкаст + тагпак + путь деплоя
                elif result_check_broadcast == False \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == False:
                    print('бродкаст - не ок ...')
                    print('тагпак - не ок ...')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - не ок ...')

                    tg_check = f'broadcast - don`t ok ...\ntagpack - don`t ok ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'

                    keyboard.add(callback_button_send_broadcast)
                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_send_all_configs_plus_path)


                elif result_check_broadcast == False \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb \
                        and result_check_deploy_path == True:
                    print('бродкаст - не ок ...')
                    print('таг пак - не ок ...')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - ок!')

                    tg_check = f'broacast - don`t ok ...\ntagpack - don`t ok ...\ndeploy - ok!'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";'
                    keyboard.add(callback_button_send_broadcast)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_broadcast_and_tag_configs)

                # исправить бродкаст + тагпак + путь деплоя
                elif result_check_broadcast == False \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:
                    print('бродкаст - не ок ...')
                    print('таг пак - не ок ...')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - не ок ...')

                    tg_check = f'broadcast - don`t ok ...\ntagpack - don`t ok ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'

                    keyboard.add(callback_button_send_broadcast)
                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_send_all_configs_plus_path)


                elif result_check_broadcast == False \
                        and result_check_tag_pack == True \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - не ок ...')
                    print('тагпак - ок!')
                    print('деплой - server - ок!')
                    print('деплой - path - ок!')
                    tg_check = f'broadcast - don`t ok ...\ntagpack - ok!\ndeploy - ok!'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}'
                    keyboard.add(callback_button_send_broadcast)

                # исправить бродкаст + путь деплоя
                elif result_check_broadcast == False \
                        and result_check_tag_pack == True \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == False:
                    print('бродкаст - не ок ...')
                    print('тагпак - ок!')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - не ок ...')

                    tg_check = f'broadcast - don`t ok ...\ntagpack - ok!\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'


                    keyboard.add(callback_button_send_broadcast)
                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_broadcast_plus_deploy_path)

                elif result_check_broadcast == None \
                        and result_check_tag_pack == True \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - нету ...')
                    print('тагпак - ок!')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - ок!')
                    tg_check = f'broadcast - no ...\ntagpack - ok!\ndeploy - ok!'
                    tg_check_error = ''

                # исправить путь деплоя
                elif result_check_broadcast == None \
                        and result_check_tag_pack == True \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == False:
                    print('бродкаст - нету ...')
                    print('тагпак - ок!')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - не ок ...')
                    tg_check = f'broadcast - no ...\ntagpack - ok!\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)


                elif result_check_broadcast == None \
                        and result_check_tag_pack == True \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - нету ...')
                    print('тагпак - ок!')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - ок!')
                    tg_check = f'broadcast - no ...\ntagpack - ok!\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";'
                    keyboard.add(callback_button_send_deploy)

                # исправить путь деплоя
                elif result_check_broadcast == None \
                        and result_check_tag_pack == True \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:
                    print('бродкаст - нету ...')
                    print('тагпак - ок!')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - не ок ...')
                    tg_check = f'broadcast - no ...\ntagpack - ok!\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)


                elif result_check_broadcast == None \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - нету ...')
                    print('таг пак - не ок ...')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - ок!')
                    tg_check = f'broadcast - no ...\ntagpack - don`t ok ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";'
                    keyboard.add(callback_button_send_deploy)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_send_tag_plus_deploy)


                # исправить тагпак + путь деплоя
                elif result_check_broadcast == None \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:
                    print('бродкаст - нету ...')
                    print('таг пак - не ок ...')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - не ок ...')

                    tg_check = f'broadcast - no ...\ntagpack - don`t ok ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_send_tag_plus_deploy_path)

                elif result_check_broadcast == None \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - нету ...')
                    print('таг пак - не ок ...')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - ок!')
                    tg_check = f'broadcast - no ...\ntagpack - don`t ok ...\ndeploy - ok!'
                    tg_check_error = f'\n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";'
                    keyboard.add(callback_button_send_tagpack)

                # исправить тагпак + путь деплоя
                elif result_check_broadcast == None \
                        and result_check_tag_pack == False \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:
                    print('бродкаст - нету ...')
                    print('таг пак - не ок ...')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - не ок ...')
                    tg_check = f'broadcast - no ...\ntagpack - don`t ok ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_tagpack)
                    keyboard.add(callback_button_send_tag_plus_deploy_path)

                elif result_check_broadcast == None \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - нету ...')
                    print('тагпак - нету ... ')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - ок!')
                    tg_check = f'broadcast - no ...\ntagpack - no ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";'
                    keyboard.add(callback_button_send_deploy)

                # исправить путь деплоя
                elif result_check_broadcast == None \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == False:
                    print('бродкаст - нету ...')
                    print('тагпак - нету ... ')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - не ок ...')
                    tg_check = f'broadcast - no ...\ntagpack - no ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)

                elif result_check_broadcast == None \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - нету ...')
                    print('таг пак - нету ... ')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - ок!')
                    tg_check = f'broadcast - no ...\ntagpack - no ...\ndeploy - ok!'
                    tg_check_error = ''

                # исправить путь деплоя
                elif result_check_broadcast == None \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == False:
                    print('бродкаст - нету ...')
                    print('тагпак - нету ... ')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - не ок ...')
                    tg_check = f'broadcast - no ...\ntagpack - no ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)

                elif result_check_broadcast == True \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - ок!')
                    print('тагпак - нету ... ')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - ок!')
                    tg_check = f'broadcast - ok!\ntagpack - no ...\ndeploy - ok!'
                    tg_check_error = ''

                # исправить путь деплоя
                elif result_check_broadcast == True \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb \
                        and result_check_deploy_path == False:
                    print('бродкаст - ок!')
                    print('тагпак - нету ... ')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - не ок ...')
                    tg_check = f'broadcast - ok!\ntagpack - no ...\ndeploy - don`t ok ...'
                    tg_chech_error = f'\n\nпрописано | надо:\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)

                elif result_check_broadcast == True \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - ок!')
                    print('таг пак - нету ... ')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - ок!')
                    tg_check = f'broadcast - ok!\ntagpack - no ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";'
                    keyboard.add(callback_button_send_deploy)

                # исправить путь деплоя
                elif result_check_broadcast == True \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == False:
                    print('бродкаст - ок!')
                    print('таг пак - нету ... ')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - не ок ...')
                    tg_check = f'broadcast - ok!\ntagpack - no ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_deploy_path)

                elif result_check_broadcast == False \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    print('бродкаст - не ок ...')
                    print('таг пак - нету ... ')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - ок!')

                    tg_check = f'broadcast - don`t ok ...\ntagpack - no ...\ndeploy - don`t ok...'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";'
                    keyboard.add(callback_button_send_deploy)
                    keyboard.add(callback_button_send_broadcast_plus_deploy)

                # исправить бродкаст + путь деплоя
                elif result_check_broadcast == False \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' not in remote_repo_address_from_wb\
                        and result_check_deploy_path == False:
                    print('бродкаст - не ок ...')
                    print('таг пак - нету ... ')
                    print('деплой - сервер - не ок ...')
                    print('деплой - путь - не ок ...')
                    tg_check = f'broadcast - don`t ok ...\ntagpack - no ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_broadcast)
                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_broadcast_plus_deploy_path)


                elif result_check_broadcast == False \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == True:
                    tg_check = f'broadcast - don`t ok...\ntagpack - no ...\ndeploy - ok!'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}'
                    keyboard.add(callback_button_send_broadcast)

                # исправить бродкаст + путь деплоя
                elif result_check_broadcast == False \
                        and result_check_tag_pack == None \
                        and '10.100.128.1:8080' in remote_repo_address_from_wb\
                        and result_check_deploy_path == False:
                    print('бродкаст - не ок ...')
                    print('таг пак - нету ... ')
                    print('деплой - сервер - ок!')
                    print('деплой - путь - не ок ...')
                    tg_check = f'broadcast - don`t ok ...\ntagpack - no ...\ndeploy - don`t ok ...'
                    tg_check_error = f'\n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{local_repo_path_from_wb}local_repo_path = "/mnt/data/local_repo";'
                    keyboard.add(callback_button_send_broadcast)
                    keyboard.add(callback_button_send_deploy_path)
                    keyboard.add(callback_button_send_broadcast_plus_deploy_path)

                else:
                    print(' - нет условия в логике')
                    tg_check = f'нет условия в логике'
                    tg_check_error = f'\n\nbroadcast - {result_check_broadcast}\ntagpack - {result_check_tag_pack}\ndeploy repo - {remote_repo_address_from_wb}\ndeploy path - {result_check_deploy_path}'



                # часть 2
                if result_check_wb_hardware == True \
                        and result_check_wb_vehicle == True \
                        and result_check_wb_mqtt_serial == True \
                        and result_check_vehicle_common_js == True:
                    tg_wb_hardware = f'wb_hardware - ok!'
                    tg_wb_vehicle = f'wb_vehicle - ok!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - ok!'
                    tg_vehicle_common_js = f'vehicle_common_js - ok!'

                # todo fix wb_hardware, wb_vehicle, wb_mqtt_serial, tg_vehicle_common_js
                elif result_check_wb_hardware == False or None \
                        and result_check_wb_vehicle == False or None \
                        and result_check_wb_mqtt_serial == False or None \
                        and result_check_vehicle_common_js == False or None:
                    tg_wb_hardware = f'wb_hardware - {result_check_wb_hardware}!'
                    tg_wb_vehicle = f'wb_vehicle - {result_check_wb_vehicle}!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - {result_check_wb_mqtt_serial}!'
                    tg_vehicle_common_js = f'vehicle_common_js - {result_check_vehicle_common_js}!'

                # todo fix , wb_vehicle, wb_mqtt_serial, tg_vehicle_common_js
                elif result_check_wb_hardware == True \
                        and result_check_wb_vehicle == False or None \
                        and result_check_wb_mqtt_serial == False or None \
                        and result_check_vehicle_common_js == False or None:
                    tg_wb_hardware = f'wb_hardware - ok!'
                    tg_wb_vehicle = f'wb_vehicle - {result_check_wb_vehicle}!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - {result_check_wb_mqtt_serial}!'
                    tg_vehicle_common_js = f'vehicle_common_js - {result_check_vehicle_common_js}!'

                # todo fix wb_hardware, , wb_mqtt_serial, tg_vehicle_common_js
                elif result_check_wb_hardware == False or None \
                        and result_check_wb_vehicle == True \
                        and result_check_wb_mqtt_serial == False or None \
                        and result_check_vehicle_common_js == False or None:
                    tg_wb_hardware = f'wb_hardware - {result_check_wb_hardware}!'
                    tg_wb_vehicle = f'wb_vehicle - ok!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - {result_check_wb_mqtt_serial}!'
                    tg_vehicle_common_js = f'vehicle_common_js - {result_check_vehicle_common_js}!'

                # todo fix wb_hardware, wb_vehicle, , tg_vehicle_common_js
                elif result_check_wb_hardware == False or None \
                        and result_check_wb_vehicle == False or None \
                        and result_check_wb_mqtt_serial == True \
                        and result_check_vehicle_common_js == False or None:
                    tg_wb_hardware = f'wb_hardware - {result_check_wb_hardware}!'
                    tg_wb_vehicle = f'wb_vehicle - {result_check_wb_vehicle}!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - ok!'
                    tg_vehicle_common_js = f'vehicle_common_js - {result_check_vehicle_common_js}!'

                # todo fix wb_hardware, wb_vehicle, wb_mqtt_serial,
                elif result_check_wb_hardware == False or None \
                        and result_check_wb_vehicle == False or None \
                        and result_check_wb_mqtt_serial == False or None \
                        and result_check_vehicle_common_js == True:
                    tg_wb_hardware = f'wb_hardware - {result_check_wb_hardware}!'
                    tg_wb_vehicle = f'wb_vehicle - {result_check_wb_vehicle}!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - {result_check_wb_mqtt_serial}!'
                    tg_vehicle_common_js = f'vehicle_common_js - ok!'

                # todo fix vehicle_common_js
                elif result_check_wb_hardware == True \
                        and result_check_wb_vehicle == True \
                        and result_check_wb_mqtt_serial == True \
                        and result_check_vehicle_common_js == False or None:
                    tg_wb_hardware = f'wb_hardware - ok!'
                    tg_wb_vehicle = f'wb_vehicle - ok!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - ok!'
                    tg_vehicle_common_js = f'vehicle_common_js - {result_check_vehicle_common_js}!'

                # todo fix wb_mqtt_serial
                elif result_check_wb_hardware == True \
                        and result_check_wb_vehicle == True \
                        and result_check_wb_mqtt_serial == False \
                        and result_check_vehicle_common_js == True:
                    tg_wb_hardware = f'wb_hardware - ok!'
                    tg_wb_vehicle = f'wb_vehicle - ok!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - {result_check_wb_mqtt_serial}!'
                    tg_vehicle_common_js = f'vehicle_common_js - ok!'

                # todo fix wb_vehicle, wb_mqtt_serial
                elif result_check_wb_hardware == True \
                        and result_check_wb_vehicle == False \
                        and result_check_wb_mqtt_serial == False \
                        and result_check_vehicle_common_js == True:
                    tg_wb_hardware = f'wb_hardware - ok!'
                    tg_wb_vehicle = f'wb_vehicle - {result_check_wb_vehicle}!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - {result_check_wb_mqtt_serial}!'
                    tg_vehicle_common_js = f'vehicle_common_js - ok!'

                # todo fix wb_hardware, wb_mqtt_serial
                elif result_check_wb_hardware == False \
                        and result_check_wb_vehicle == True \
                        and result_check_wb_mqtt_serial == False \
                        and result_check_vehicle_common_js == True:
                    tg_wb_hardware = f'wb_hardware - {result_check_wb_hardware}!'
                    tg_wb_vehicle = f'wb_vehicle - ok!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - {result_check_wb_mqtt_serial}!'
                    tg_vehicle_common_js = f'vehicle_common_js - ok!'

                # todo fix wb_vehicle, vehicle_common_js
                elif result_check_wb_hardware == True \
                        and result_check_wb_vehicle == False \
                        and result_check_wb_mqtt_serial == True \
                        and result_check_vehicle_common_js == False:
                    tg_wb_hardware = f'wb_hardware - ok!'
                    tg_wb_vehicle = f'wb_vehicle - {result_check_wb_vehicle}!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - ok!'
                    tg_vehicle_common_js = f'vehicle_common_js - {result_check_vehicle_common_js}!'

                # todo fix wb_mqtt_serial, vehicle_common_js
                elif result_check_wb_hardware == True \
                        and result_check_wb_vehicle == True \
                        and result_check_wb_mqtt_serial == False \
                        and result_check_vehicle_common_js == False:
                    tg_wb_hardware = f'wb_hardware - ok!'
                    tg_wb_vehicle = f'wb_vehicle - ok!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - {result_check_wb_mqtt_serial}!'
                    tg_vehicle_common_js = f'vehicle_common_js - {result_check_vehicle_common_js}!'

                # todo fix wb_hardware, wb_vehicle
                elif result_check_wb_hardware == False \
                        and result_check_wb_vehicle == False \
                        and result_check_wb_mqtt_serial == True \
                        and result_check_vehicle_common_js == True:
                    tg_wb_hardware = f'wb_hardware - {result_check_wb_hardware}!'
                    tg_wb_vehicle = f'wb_vehicle - {result_check_wb_vehicle}!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - ok!'
                    tg_vehicle_common_js = f'vehicle_common_js - ok!'

                # todo fix wb_hardware, vehicle_common_js
                elif result_check_wb_hardware == False \
                        and result_check_wb_vehicle == True \
                        and result_check_wb_mqtt_serial == True \
                        and result_check_vehicle_common_js == False:
                    tg_wb_hardware = f'wb_hardware - {result_check_wb_hardware}!'
                    tg_wb_vehicle = f'wb_vehicle - ok!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - ok!'
                    tg_vehicle_common_js = f'vehicle_common_js - {result_check_vehicle_common_js}!'

                # todo fix wb_vehicle
                elif result_check_wb_hardware == True \
                        and result_check_wb_vehicle == False \
                        and result_check_wb_mqtt_serial == True \
                        and result_check_vehicle_common_js == True:
                    tg_wb_hardware = f'wb_hardware - ok!'
                    tg_wb_vehicle = f'wb_vehicle - {result_check_wb_vehicle}!'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - ok!'
                    tg_vehicle_common_js = f'vehicle_common_js - ok!'

                else:
                    print(' - нет условия!!!')
                    tg_wb_hardware = f'wb_hardware - {result_check_wb_hardware}!'
                    tg_wb_vehicle = f'wb_vehicle - {result_check_wb_vehicle}'
                    tg_wb_mqtt_serial = f'wb_mqtt_serial - {result_check_wb_mqtt_serial}!'
                    tg_vehicle_common_js = f'vehicle_common_js - {result_check_vehicle_common_js}!'

                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n{tg_check}\n{tg_wb_hardware}\n{tg_wb_vehicle}\n{tg_wb_mqtt_serial}\n{tg_vehicle_common_js}{tg_check_error}', reply_markup=keyboard)


            elif all_configs_data == TimeoutError:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - TimeoutError!\n - повторяю попытку ...', reply_markup=keyboard)

        except AttributeError:
            thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                      args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
            thread.start()
            thread.join()
            try:
                all_configs_data = thread.result
                if all_configs_data != TimeoutError:
                    try:
                        broadcast_address_from_wirenboard = str(all_configs_data[2])
                    except TypeError:
                        broadcast_address_from_wirenboard = None

                    print('broadcast_address_from_wirenboard: ', broadcast_address_from_wirenboard)
                    print('function_tackpack_config_create_result: ', function_tackpack_config_create_result)

                    if function_tackpack_config_create_result == None:
                        print('tag_pack - None, pass!')
                        pass

                    else:
                        tag_device_number_from_table = function_tackpack_config_create_result[0]
                        tag_device_secret_from_table = function_tackpack_config_create_result[1]
                        print('tag_device_number_from_table: ', tag_device_number_from_table)
                        print('tag_device_secret_from_table: ', tag_device_secret_from_table)

                    for line in all_configs_data:
                        if 'tag_address' in line:
                            tag_address_from_wirenboard = line
                            print('tag_adress_from_wirenboard: ', tag_address_from_wirenboard)
                        elif 'tag_device_number' in line:
                            tag_device_number_from_wirenboard = line
                            print('tag_device_number_from_wirenboard: ', tag_device_number_from_wirenboard)
                        elif 'tag_device_secret' in line:
                            tag_device_secret_from_wirenboard = line
                            print('tag_device_secret_from_wirenboard: ', tag_device_secret_from_wirenboard)
                            print('broadcast_address_from_wirenboard: ', broadcast_address_from_wirenboard)
                        elif 'remote_repo_address' in line:
                            remote_repo_address_from_wb = line
                            print('remote_repo_address_from_wb: ', remote_repo_address_from_wb)
                        else:
                            pass

                    # проверка бродкаста
                    def check_broadcast():
                        if reg_num == 'None':
                            print('reg_num none')
                            return None
                        if function_broadcast_config_create_result == None:
                            print('broadcast none')
                            return None
                        if function_broadcast_config_create_result in broadcast_address_from_wirenboard:
                            print('broadcast True')
                            return True
                        elif function_broadcast_config_create_result not in broadcast_address_from_wirenboard:
                            print('broadcast False')
                            return False
                        else:
                            print('broadcast pass')
                            return False

                    # проверка таг пака
                    def check_tag_pack():
                        # print()
                        if function_tackpack_config_create_result == None:
                            print('tag_create: ', function_tackpack_config_create_result)
                            return None
                        #     pass
                        if tag_device_number_from_table == None or tag_device_secret_from_table == None:
                            print('tag_device_number_from_table: ', tag_device_number_from_table)
                            print('tag_device_secret_from_table: ', tag_device_secret_from_table)
                            return None
                        if tag_device_number_from_table in tag_device_number_from_wirenboard and tag_device_secret_from_table in tag_device_secret_from_wirenboard and '194.226.138.63' in tag_address_from_wirenboard:
                            print('dev_id - ok')
                            print('dev_pass - ok')
                            print('tag_address - ok')
                            return True
                        elif tag_device_number_from_table not in tag_device_number_from_wirenboard:
                            print('dev_id - don`t ok')
                            print('надо: ', tag_device_number_from_table)
                            print('установлено: ', tag_device_number_from_wirenboard)
                            return False
                        elif tag_device_secret_from_table not in tag_device_secret_from_wirenboard:
                            print('dev_pass - don`t ok')
                            return False
                        elif '194.226.138.63' not in tag_address_from_wirenboard:
                            print('tag_address - don`t ok')
                            return False
                        else:
                            print('нет условия!')

                    result_check_broadcast = check_broadcast()
                    result_check_tag_pack = check_tag_pack()

                    print('result_check_tag_pack: ', result_check_tag_pack)
                    print('result_check_broadcast: ', result_check_broadcast)



                    if result_check_broadcast and result_check_tag_pack == True and '10.100.128.1:8080' in remote_repo_address_from_wb:
                        print('бродкаст - ок!')
                        print('таг пак - ок!')
                        print('деплой - ок!')
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - ок!\nтаг пак - ок!\nдеплой - ок!\n',
                                              reply_markup=keyboard)
                    elif result_check_broadcast and result_check_tag_pack == True and '10.100.128.1:8080' not in remote_repo_address_from_wb:
                        print('бродкаст - ок!')
                        print('таг пак - ок!')
                        print('деплой - don`t ок!')
                        deploy_config_send = str('deploy_send ' + ip + ' ' + reg_num)
                        callback_button_send = types.InlineKeyboardButton(text="исправить деплой", callback_data=deploy_config_send)
                        keyboard.add(callback_button_send)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - ок! \nтаг пак - ок!\nдеплой - не ок ... \n\nпрописан:\n{remote_repo_address_from_wb}а надо: \nremote_repo_address = "http://10.100.128.1:8080";',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == True and result_check_tag_pack == False and '10.100.128.1:8080' not in remote_repo_address_from_wb:
                        print('бродкаст - ок!')
                        print('таг пак - don`t ок!')
                        print('деплой - don`t ок!')
                        dev_id = tag_device_number_from_table
                        dev_id_pass = tag_device_secret_from_table
                        deploy_config_send = str('deploy_send ' + ip + ' ' + reg_num)
                        tag_pack_config_send = str('tag_send ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                        deploy_and_tag_configs_send = str('d_t_c ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                        callback_button_send_deploy = types.InlineKeyboardButton(text="исправить деплой",
                                                                                 callback_data=deploy_config_send)
                        callback_button_send_tagpack = types.InlineKeyboardButton(text="исправить таг пак",
                                                                                  callback_data=tag_pack_config_send)
                        callback_button_send_tag_plus_deploy = types.InlineKeyboardButton(text="исправить таг пак + деплой",
                                                                                          callback_data=deploy_and_tag_configs_send)
                        keyboard.add(callback_button_send_deploy)
                        keyboard.add(callback_button_send_tagpack)
                        keyboard.add(callback_button_send_tag_plus_deploy)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - ок!\nтаг пак - не ок ... \nдеплой - не ок ... \n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";',
                                              reply_markup=keyboard)

                    elif result_check_broadcast == True and result_check_tag_pack == False and '10.100.128.1:8080' in remote_repo_address_from_wb:
                        print('бродкаст - ок!')
                        print('таг пак - не ок ...')
                        print('деплой - ок!')

                        dev_id = tag_device_number_from_table
                        dev_id_pass = tag_device_secret_from_table
                        tag_pack_config_send = str('tag_send ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                        callback_button_send_tagpack = types.InlineKeyboardButton(text="исправить таг пак",
                                                                                  callback_data=tag_pack_config_send)
                        keyboard.add(callback_button_send_tagpack)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - ок!\nтаг пак - не ок ... \nдеплой - ок! \n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";',
                                              reply_markup=keyboard)


                    elif result_check_broadcast == False and result_check_tag_pack == True and '10.100.128.1:8080' not in remote_repo_address_from_wb:
                        print('бродкаст - don`t ок!')
                        print('таг пак - ок!')
                        print('деплой - don`t ок!')
                        deploy_config_send = str('deploy_send ' + ip + ' ' + reg_num)
                        deploy_and_broadcast_configs_send = str(
                            'd_and_b_conf ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                        broadcast_config_send = str(
                            'broad_send ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                        callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст",
                                                                                    callback_data=broadcast_config_send)
                        callback_button_send_deploy = types.InlineKeyboardButton(text="исправить деплой",
                                                                                 callback_data=deploy_config_send)
                        callback_button_send_broadcast_plus_deploy = types.InlineKeyboardButton(text="исправить бродкаст + деплой",
                                                                                                callback_data=deploy_and_broadcast_configs_send)
                        keyboard.add(callback_button_send_broadcast)
                        keyboard.add(callback_button_send_deploy)
                        keyboard.add(callback_button_send_broadcast_plus_deploy)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - не ок ...\nтаг пак - ок!\nдеплой - не ок ... \n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == False and result_check_tag_pack == False and '10.100.128.1:8080' not in remote_repo_address_from_wb:
                        print('бродкаст - don`t ок!')
                        print('таг пак - don`t ок!')
                        print('деплой - don`t ок!')

                        dev_id = tag_device_number_from_table
                        dev_id_pass = tag_device_secret_from_table
                        deploy_config_send = str('deploy_send ' + ip + ' ' + reg_num)
                        tag_pack_config_send = str('tag_send ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                        broadcast_config_send = str('broad_send ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                        send_all_configs_send = str('s_all ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result + ' ' + ' ' + short_sn)
                        print('send_all_configs_send: ', send_all_configs_send)

                        callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст", callback_data=broadcast_config_send)
                        callback_button_send_deploy = types.InlineKeyboardButton(text="исправить деплой", callback_data=deploy_config_send)
                        callback_button_send_tagpack = types.InlineKeyboardButton(text="исправить таг пак", callback_data=tag_pack_config_send)
                        callback_button_send_all_configs_send = types.InlineKeyboardButton(text="*исправить бродкаст + деплой + таг пак", callback_data=send_all_configs_send)
                        keyboard.add(callback_button_send_broadcast)
                        keyboard.add(callback_button_send_deploy)
                        keyboard.add(callback_button_send_tagpack)
                        keyboard.add(callback_button_send_all_configs_send)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - не ок ... \nтаг пак - не ок ... \nдеплой - не ок ... \n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == False and result_check_tag_pack == False and '10.100.128.1:8080' in remote_repo_address_from_wb:
                        print('бродкаст - не ок ...')
                        print('таг пак - не ок ...')
                        print('деплой - ок!')

                        dev_id = tag_device_number_from_table
                        dev_id_pass = tag_device_secret_from_table
                        tag_pack_config_send = str('tag_send ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                        broadcast_config_send = str('broad_send ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                        broadcast_and_tag_configs_send = str('broad_tag_conf ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result + ' ' + short_sn)
                        print('send_all_configs_send: ', broadcast_and_tag_configs_send)

                        callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст", callback_data=broadcast_config_send)
                        callback_button_send_tagpack = types.InlineKeyboardButton(text="исправить таг пак", callback_data=tag_pack_config_send)
                        callback_button_broadcast_and_tag_configs_send = types.InlineKeyboardButton(text="исправить бродкаст + таг пак", callback_data=broadcast_and_tag_configs_send)
                        keyboard.add(callback_button_send_broadcast)
                        keyboard.add(callback_button_send_tagpack)
                        keyboard.add(callback_button_broadcast_and_tag_configs_send)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - не ок ... \nтаг пак - не ок ... \nдеплой - ок! \n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";',
                                              reply_markup=keyboard)


                    elif result_check_broadcast == False and result_check_tag_pack == True and '10.100.128.1:8080' in remote_repo_address_from_wb:
                        print('бродкаст - don`t ок!')
                        print('таг пак - ок!')
                        print('деплой - ок!')
                        broadcast_config_send = str(
                            'broad_send ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                        callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст",
                                                                                    callback_data=broadcast_config_send)
                        keyboard.add(callback_button_send_broadcast)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - не ок ...\nтаг пак - ок!\nдеплой - ок! \n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == None and result_check_tag_pack == True and '10.100.128.1:8080' in remote_repo_address_from_wb:
                        print('бродкаст - нету ...')
                        print('таг пак - ок!')
                        print('деплой - ок!')
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - нету ...\nтаг пак - ок!\nдеплой - ок!\n',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == None and result_check_tag_pack == True and '10.100.128.1:8080' not in remote_repo_address_from_wb:
                        print('бродкаст - нету ...')
                        print('таг пак - ок!')
                        print('деплой - don`t ок!')
                        deploy_config_send = str('deploy_send ' + ip + ' ' + reg_num)
                        callback_button_send = types.InlineKeyboardButton(text="исправить деплой", callback_data=deploy_config_send)
                        keyboard.add(callback_button_send)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - нету ... \nтаг пак - ок!\nдеплой - не ок ... \n\nпрописан:\n{remote_repo_address_from_wb}а надо: \nremote_repo_address = "http://10.100.128.1:8080";',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == None and result_check_tag_pack == False and '10.100.128.1:8080' not in remote_repo_address_from_wb:
                        print('бродкаст - нету ...')
                        print('таг пак - don`t ок!')
                        print('деплой - don`t ок!')
                        dev_id = tag_device_number_from_table
                        dev_id_pass = tag_device_secret_from_table
                        deploy_config_send = str('deploy_send ' + ip + ' ' + reg_num)
                        tag_pack_config_send = str('tag_send ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                        deploy_and_tag_configs_send = str('d_t_c ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                        callback_button_send_deploy = types.InlineKeyboardButton(text="исправить деплой",
                                                                                 callback_data=deploy_config_send)
                        callback_button_send_tagpack = types.InlineKeyboardButton(text="исправить таг пак",
                                                                                  callback_data=tag_pack_config_send)
                        callback_button_send_tag_plus_deploy = types.InlineKeyboardButton(text="исправить таг пак + деплой",
                                                                                          callback_data=deploy_and_tag_configs_send)
                        keyboard.add(callback_button_send_deploy)
                        keyboard.add(callback_button_send_tagpack)
                        keyboard.add(callback_button_send_tag_plus_deploy)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - нету ... \nтаг пак - не ок ... \nдеплой - не ок ... \n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == None and result_check_tag_pack == False and '10.100.128.1:8080' in remote_repo_address_from_wb:
                        print('бродкаст - нету ...')
                        print('таг пак - не ок ...')
                        print('деплой - ок!')
                        dev_id = tag_device_number_from_table
                        dev_id_pass = tag_device_secret_from_table
                        tag_pack_config_send = str('tag_send ' + ip + ' ' + reg_num + ' ' + dev_id + ' ' + dev_id_pass)
                        callback_button_send_tagpack = types.InlineKeyboardButton(text="исправить таг пак",
                                                                                  callback_data=tag_pack_config_send)
                        keyboard.add(callback_button_send_tagpack)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - нету ... \nтаг пак - не ок ... \nдеплой - ок! \n\nпрописано | надо:\n{tag_device_number_from_wirenboard}tag_device_number = "{tag_device_number_from_table}";\n{tag_device_secret_from_wirenboard}tag_device_secret = "{tag_device_secret_from_table}";',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == None and result_check_tag_pack == None and '10.100.128.1:8080' not in remote_repo_address_from_wb:
                        print('бродкаст - нету ...')
                        print('таг пак - нету ... ')
                        print('деплой - не ок ...')
                        deploy_config_send = str('deploy_send ' + ip + ' ' + reg_num)
                        callback_button_send_deploy = types.InlineKeyboardButton(text="исправить деплой",
                                                                                 callback_data=deploy_config_send)
                        keyboard.add(callback_button_send_deploy)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаста - нету ... \nтаг пака - нету ... \nдеплой - не ок ... \n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == None and result_check_tag_pack == None and '10.100.128.1:8080' in remote_repo_address_from_wb:
                        print('бродкаст - нету ...')
                        print('таг пак - нету ... ')
                        print('деплой - ок!')
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаста - нету ...\nтаг пака - нету ...\nдеплой - ок!\n',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == True and result_check_tag_pack == None and '10.100.128.1:8080' in remote_repo_address_from_wb:
                        print('бродкаст - ок!')
                        print('таг пак - нету ... ')
                        print('деплой - ок!')
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - ок!\nтаг пака - нету ...\nдеплой - ок!\n',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == True and result_check_tag_pack == None and '10.100.128.1:8080' not in remote_repo_address_from_wb:
                        print('бродкаст - ок!')
                        print('таг пак - нету ... ')
                        print('деплой - не ок ...')

                        deploy_config_send = str('deploy_send ' + ip + ' ' + reg_num)
                        callback_button_send_deploy = types.InlineKeyboardButton(text="исправить деплой",
                                                                                 callback_data=deploy_config_send)
                        keyboard.add(callback_button_send_deploy)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - ок!\nтаг пака - нету ... \nдеплой - не ок ... \n\nпрописано | надо:\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == False and result_check_tag_pack == None and '10.100.128.1:8080' not in remote_repo_address_from_wb:
                        print('бродкаст - не ок ...')
                        print('таг пак - нету ... ')
                        print('деплой - не ок ...')

                        broadcast_config_send = str(
                            'broad_send ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                        deploy_config_send = str('deploy_config_send ' + ip + ' ' + reg_num)
                        deploy_and_broadcast_configs_send = str(
                            'deploy_and_broadcast_configs ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                        callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст",
                                                                                    callback_data=broadcast_config_send)
                        callback_button_send_deploy = types.InlineKeyboardButton(text="исправить деплой",
                                                                                 callback_data=deploy_config_send)
                        callback_button_send_broadcast_plus_deploy = types.InlineKeyboardButton(text="исправить бродкаст + деплой",
                                                                                                callback_data=deploy_and_broadcast_configs_send)
                        keyboard.add(callback_button_send_broadcast)
                        keyboard.add(callback_button_send_deploy)
                        keyboard.add(callback_button_send_broadcast_plus_deploy)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - не ок ...\nтаг пака - нету ... \nдеплой - не ок ... \n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}\n\n{remote_repo_address_from_wb}remote_repo_address = "http://10.100.128.1:8080";',
                                              reply_markup=keyboard)
                    elif result_check_broadcast == False and result_check_tag_pack == None and '10.100.128.1:8080' in remote_repo_address_from_wb:
                        print('бродкаст - не ок ...')
                        print('таг пак - нету ... ')
                        print('деплой - ок!')

                        broadcast_config_send = str('broad_send ' + ip + ' ' + reg_num + ' ' + function_broadcast_config_create_result)
                        callback_button_send_broadcast = types.InlineKeyboardButton(text="исправить бродкаст", callback_data=broadcast_config_send)
                        keyboard.add(callback_button_send_broadcast)
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{call.message.text}\n\nбродкаст - не ок ...\nтаг пака - нету ... \nдеплой - ок! \n\nпрописано | надо:\n{broadcast_address_from_wirenboard}  address {function_broadcast_config_create_result}',
                                              reply_markup=keyboard)

                    else:
                        print('нет условия в логике')
                elif all_configs_data == TimeoutError:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - TimeoutError!\n - не удалось получить данные.',
                                          reply_markup=keyboard)
                else:
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{call.message.text}\n\n - TimeoutError!\n - нет условия!\n - result:\n{all_configs_data}\n - не удалось получить данные.',
                                          reply_markup=keyboard)
            except Exception as e:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n\n - AttributeError!\n - Exception:\n{e.with_traceback()}\n - не удалось получить данные.',
                                      reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n\n - Exception:\n{e.with_traceback()}\n - не удалось получить данные.',
                                  reply_markup=keyboard)

    # reboot wirenboard
    elif 'reboot_wirenboard' in call.data:
        ip = call.data.split()[1]

        # ssh reboot
        # command = 'reboot'
        # threadname = f'reboot_command {ip} | {call.message.chat.username}'
        # thread = ThreadWithResult(target=ssh_connect, name=threadname, args=[ip, config.wirenboard_username, config.wirenboard_password, command])
        # thread.start()
        # thread.join()
        # bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{call.message.text}\n - {ip} отправлен в перезагрузку.')

        # mqtt reboot
        result = os.system(f"mosquitto_pub -h {ip} -t '/devices/system/controls/Reboot/on' -m 1")
        print(result)
        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                              text=f'{call.message.text}\n - {ip} отправлен в перезагрузку.')

    # проверка конфига CAN + потерь в tail логах + статус службы
    elif 'can_read' in call.data:
        input_tg = call.data.split()
        print(input_tg)
        ip = input_tg[1]
        reg_num = input_tg[2]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
        keyboard = types.InlineKeyboardMarkup()

        spreadsheet_id = config.can_table
        major = 'ROWS'
        range_visit = 'Посещено!A1:I120'
        # range_not_visit = 'Непроверено!B1:K50'
        sheet_broadcats_visit = google_sheets_read(spreadsheet_id, range_visit, major)
        # sheet_broadcats_not_visit = google_sheets_read(spreadsheet_id, range_not_visit, major)

        for row in sheet_broadcats_visit:
            if reg_num in row:
                line_in_range_visit = row
                print(' - найдено в range_visit: ', line_in_range_visit)

                dev_id_from_table = line_in_range_visit[0]
                brand_from_table = line_in_range_visit[1]
                reg_num_from_table = line_in_range_visit[2]
                config_version_from_table = line_in_range_visit[4]
                try:
                    date_from_table = line_in_range_visit[7]
                except IndexError:
                    date_from_table = 'None'
                    print(' - в таблице нету даты!')
                try:
                    notes_from_table = line_in_range_visit[8]
                except IndexError:
                    notes_from_table = 'None'
                    print(' - в таблице нету заметок!')

                result_tg = f'{call.message.text}\n\nданные из таблицы:\nreg_num: {reg_num_from_table}\ndev_id: {dev_id_from_table}\nbrand: {brand_from_table}\nconfig: {config_version_from_table}\ndate update: {date_from_table}\nnotes: {notes_from_table}\n'
                function_mqtt_about_sensors = str('function_mqtt_about_sensors ' + ip + ' ' + reg_num)
                keyboard = types.InlineKeyboardMarkup()
                callback_button_about_sensors = types.InlineKeyboardButton(text="об оборудовании", callback_data=function_mqtt_about_sensors)
                keyboard.add(callback_button_about_sensors)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=result_tg, reply_markup=keyboard)


                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{result_tg}\n - занимаюсь {ip} ...')

                command = f'cat /etc/canmqttd.json; tail -n50 /var/log/messages | grep canmqtt; service can-mqtt status'
                threadname = f'check_can_read {ip} | {call.message.chat.username}'
                thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                          args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
                thread.start()
                thread.join()

                try:
                    can_read_wirenboard = thread.result

                    if len(can_read_wirenboard) > 1:
                        print(' - can_read_wirenboard: ', can_read_wirenboard)
                        vehicle_type_wirenboard, status_service_can_status, status_service_can_status_2, time_service_can_status = 'None'
                        timedout_in_line = 'None'
                        vehicle_type_wirenboard = 'None'

                        for line in can_read_wirenboard:
                            if can_read_wirenboard == 'None':
                                print(' - нетю ...')
                            elif 'vehicle_type' in line:
                                vehicle_type_wirenboard = line.split()[1:]
                                vehicle_type_wirenboard = " ".join(vehicle_type_wirenboard)
                                vehicle_type_wirenboard = str(vehicle_type_wirenboard).replace("\"", "").replace(",", "")
                                print(' --- vehicle_type_wirenboard: ', vehicle_type_wirenboard)
                            elif 'Active:' in line:
                                status_service_can = line.split()
                                status_service_can_status = status_service_can[1]
                                status_service_can_status_2 = status_service_can[2]
                                time_service_can_status = status_service_can[-2] + ' ' + status_service_can[-1]
                                if 'days' in line:
                                    time_service_can_status = status_service_can[-3] + ' ' + status_service_can[-2] + ' ' + \
                                                              status_service_can[-1]
                                print(' --- Active: ', status_service_can_status, '|', status_service_can_status_2, '|',
                                      time_service_can_status)
                            elif 'timed out' in line:
                                timedout_in_line = "True"
                                print(' - !!! timed out: ', line)
                            else:
                                pass

                        function_ping = str('function_ping ' + ip + ' ' + reg_num)
                        sleep = str('sleep ' + ip + ' ' + reg_num)
                        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

                        if timedout_in_line == "True" and status_service_can_status == 'active':
                            can_result_timeout_and_status = f'\n - служба активна.\n - идут потери!'
                        elif timedout_in_line == "True" and status_service_can_status != 'active':
                            can_result_timeout_and_status = f'\n - служба НЕ активна ...\n - идут потери!'
                        elif timedout_in_line == 'None' and status_service_can_status == 'active':
                            can_result_timeout_and_status = f'\n - служба активна!\n - потерь нет.'
                        elif timedout_in_line == 'None' and status_service_can_status != 'active':
                            can_result_timeout_and_status = f'\n - служба НЕ активна ...\n - потерь нет.'

                        else:
                            print()
                            print('timedout_in_line: ', timedout_in_line)
                            print('status_service_can_status: ', status_service_can_status)
                            print()

                        if config_version_from_table == None:
                            pass
                        # Felis 2 V2020
                        elif config_version_from_table == 'Felis 2 V2020':
                            print('# config: ', config_version_from_table)
                            if 'Felis 2 V2020' or 'Holmer Terra Felis 2 V2020' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить Holmer Terra Felis 2 V2020.sh ? - НУЖЕН")
                                print(' - установить Holmer Terra Felis 2 V2021.sh ?')

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Felis_2_V2020')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Felis_2_V2021')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить Holmer Terra Felis 2 V2020", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Felis 2 V2021", callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить Holmer Terra Felis 2 V2020.sh ? - НУЖЕН")
                                print(' - установить Holmer Terra Felis 2 V2021.sh ?')
                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Felis_2_V2020')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Felis_2_V2021')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить #Holmer Terra Felis 2 V2020#", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Felis 2 V2021", callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                        # Felis 2 V2021
                        elif config_version_from_table == 'Felis 2 V2021':
                            print('# config: ', config_version_from_table)
                            if 'Felis 2 V2021' or 'Holmer Terra Felis 2 V2021' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(' - переустановить Holmer Terra Felis 2 V2021.sh ? - НУЖЕН')
                                print(" - установить Holmer Terra Felis 2 V2020.sh ?")

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Felis_2_V2021')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Felis_2_V2020')
                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить Holmer Terra Felis 2 V2021", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Felis 2 V2020", callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(' - установить Holmer Terra Felis 2 V2021.sh ? - НУЖЕН')
                                print(" - установить Holmer Terra Felis 2 V2020.sh ?")

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Felis_2_V2021')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Felis_2_V2020')
                                can_result_config = f'\n - конфиг CAN не ок ... \nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить #Holmer Terra Felis 2 V2021#", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Felis 2 V2020", callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)

                        # M-VF0-adv-10s
                        elif config_version_from_table == 'M-VF0-adv-10s':
                            print('# config: ', config_version_from_table)
                            if 'MAUS_VF0-adv-noloader-10s' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить MAUS_VF0-adv-noloader-10s.sh ? - НУЖЕН")
                                print(" - установить MAUS_VF00-adv-noloader-10s.sh ?")
                                print(" - установить MAUS_V21-01-adv-noload.sh ?")

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_VF0-adv-noloader-10s')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_VF00-adv-noloader-10s')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_V21-01-adv-noload')
                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить #MAUS_VF0-adv-noloader-10s#", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF00-adv-noloader-10s", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_V21-01-adv-noload", callback_data=install_can_3)

                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить MAUS_VF0-adv-noloader-10s.sh ? - НУЖЕН")
                                print(" - установить MAUS_VF00-adv-noloader-10s.sh ?")
                                print(" - установить MAUS_V21-01-adv-noload.sh ?")

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_VF0-adv-noloader-10s')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_VF00-adv-noloader-10s')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_V21-01-adv-noload')
                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить #MAUS_VF0-adv-noloader-10s#", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF00-adv-noloader-10s", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_V21-01-adv-noload", callback_data=install_can_3)

                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                        # M-VF00-10s
                        elif config_version_from_table == 'M-VF00-10s' or config_version_from_table == 'M-VF00-adv-10s':
                            print('# config: ', config_version_from_table)
                            if 'MAUS_VF00-adv-noloader-10s' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить MAUS_VF00-adv-noloader-10s.sh ? - НУЖЕН")
                                print(" - установить MAUS_VF0-adv-noloader-10s.sh ?")
                                print(" - установить MAUS_V21-01-adv-noload.sh ?")

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_VF00-adv-noloader-10s')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_VF0-adv-noloader-10s')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_V21-01-adv-noload')
                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить #MAUS_VF00-adv-noloader-10s#", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF0-adv-noloader-10s", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_V21-01-adv-noload", callback_data=install_can_3)

                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить MAUS_VF00-adv-noloader-10s.sh ? - НУЖЕН")
                                print(" - установить MAUS_VF0-adv-noloader-10s.sh ?")
                                print(" - установить MAUS_V21-01-adv-noload.sh ?")

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_VF00-adv-noloader-10s')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_VF0-adv-noloader-10s')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_V21-01-adv-noload')
                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить #MAUS_VF00-adv-noloader-10s#", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF0-adv-noloader-10s", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_V21-01-adv-noload", callback_data=install_can_3)

                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                        # MAUS_9093-adv-no...
                        elif config_version_from_table == 'MAUS_9093-adv-no...':
                            print('# config: ', config_version_from_table)
                            if 'MAUS_9093-adv-noloader-10s' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить MAUS_9093-adv-noloader-10s.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_9093-adv-noloader-10s')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить MAUS_9093-adv-noloader-10s", callback_data=install_can_1)
                                keyboard.add(callback_button_install_1)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить MAUS_9093-adv-noloader-10s.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAUS_9093-adv-noloader-10s')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить MAUS_9093-adv-noloader-10s", callback_data=install_can_1)
                                keyboard.add(callback_button_install_1)

                        # T2 LOADER V0
                        elif config_version_from_table == 'T2 LOADER V0':
                            print('# config: ', config_version_from_table)
                            if 'Holmer Terra Dos T2 LOADER V0' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить Holmer Terra Dos T2 LOADER V0.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T2_LOADER_V0')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить Holmer Terra Dos T2 LOADER V0", callback_data=install_can_1)
                                keyboard.add(callback_button_install_1)
                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить Holmer Terra Dos T2 LOADER V0.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T2 LOADER V0')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить Holmer Terra Dos T2 LOADER V0", callback_data=install_can_1)
                                keyboard.add(callback_button_install_1)
                        # T3 V0
                        elif config_version_from_table == 'T3 V0':
                            print('# config: ', config_version_from_table)
                            if 'Holmer Terra Dos T3 V0' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить Holmer Terra Dos T3 V0.sh ? - НУЖЕН")
                                print(" - установить Holmer Terra Dos T3 V1.sh ?")
                                print(" - установить Holmer Terra Dos T3 V2.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V0')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V1')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V2')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить Holmer Terra Dos T3 V0", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V1", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V2", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить Holmer Terra Dos T3 V0.sh ? - НУЖЕН")
                                print(" - установить Holmer Terra Dos T3 V1.sh ?")
                                print(" - установить Holmer Terra Dos T3 V2.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V0')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V1')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V2')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V0", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V1", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V2", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                        # T3 V0 2022
                        elif config_version_from_table == 'T3 V0 2022':
                            print('# config: ', config_version_from_table)
                            print(' - немного не понял, насчет этой версии, че за 2022, думаю, это версия V2.')
                            if 'Holmer Terra Dos T3 V2' or 'Holmer Terra Dos T3 V0 2022' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить Holmer Terra Dos T3 V2.sh ? - НУЖЕН")
                                print(" - установить Holmer Terra Dos T3 V1.sh ?")
                                print(" - установить Holmer Terra Dos T3 V0.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.\n - немного не понял, насчет этой версии, че за 2022, думаю, это версия V2.'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V2')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V1')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V0')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить Holmer Terra Dos T3 V2", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V1", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V0", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить Holmer Terra Dos T3 V2.sh ? - НУЖЕН")
                                print(" - установить Holmer Terra Dos T3 V1.sh ?")
                                print(" - установить Holmer Terra Dos T3 V0.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}\n\n - немного не понял, насчет этой версии, че за 2022, думаю, это версия V2.'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V2')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V1')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V0')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V2", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V1", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V0", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                        # T3 V1
                        elif config_version_from_table == 'T3 V1':
                            print('# config: ', config_version_from_table)
                            if 'Holmer Terra Dos T3 V1' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить Holmer Terra Dos T3 V1.sh ? - НУЖЕН")
                                print(" - установить Holmer Terra Dos T3 V0.sh ?")
                                print(" - установить Holmer Terra Dos T3 V2.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V1')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V0')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V2')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить Holmer Terra Dos T3 V1", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V0", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V2", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить Holmer Terra Dos T3 V0.sh ?")
                                print(" - установить Holmer Terra Dos T3 V1.sh ? - НУЖЕН")
                                print(" - установить Holmer Terra Dos T3 V2.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V1')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V0')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T3_V2')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V1", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V0", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить Holmer Terra Dos T3 V2", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                        # T4-40_VF0-10s
                        elif config_version_from_table == 'T4-40_VF0-10s':
                            print('# config: ', config_version_from_table)
                            if 'Holmer_Terra_Dos_T4-40_VF0-10s' or 'Holmer Terra Dos T4-40 VF0 10s' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить Holmer_Terra_Dos_T4-40_VF0-10s.sh ? - НУЖЕН")
                                print(" - установить Holmer_Terra_Dos_T4-40_VF0-adv-10s.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T4-40_VF0-10s')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T4-40_VF0-adv-10s')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="переустановить T4-40 VF0 10s",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить T4-40 VF0 adv 10s",
                                                                                       callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить Holmer_Terra_Dos_T4-40_VF0-10s.sh ? - НУЖЕН")
                                print(" - установить Holmer_Terra_Dos_T4-40_VF0-adv-10s.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T4-40_VF0-10s')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T4-40_VF0-adv-10s')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="установить T4-40 VF0 10s",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить T4-40 VF0 adv 10s",
                                                                                       callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)

                        # T4-40_VF0-adv-10s
                        elif config_version_from_table == 'T4-40_VF0-adv-10s':
                            print('# config: ', config_version_from_table)
                            if 'Holmer_Terra_Dos_T4-40_VF0-adv-10s' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить Holmer_Terra_Dos_T4-40_VF0-adv-10s.sh ? - НУЖЕН")
                                print(" - установить Holmer_Terra_Dos_T4-40_VF0-10s.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T4-40_VF0-10s')
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T4-40_VF0-adv-10s')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить T4-40 VF0 adv 10s", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить T4-40 VF0 10s",
                                                                                       callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить Holmer_Terra_Dos_T4-40_VF0-adv-10s.sh ? - НУЖЕН")
                                print(" - установить Holmer_Terra_Dos_T4-40_VF0-10s.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T4-40_VF0-10s')
                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'T4-40_VF0-adv-10s')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="установить T4-40 VF0 adv 10s",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить T4-40 VF0 10s",
                                                                                       callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)

                        # TIGER_4_VF0 or TIGER_4_VF0_10s
                        elif config_version_from_table == 'TIGER_4_VF0' or config_version_from_table == 'TIGER_4_VF0_10s' or config_version_from_table == 'TIGER_4_VF0-10s':
                            print('# config: ', config_version_from_table)
                            if 'ROPA_EURO_TIGER_4_VF0-adv' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить ROPA_EURO_TIGER_4_VF0-adv.sh ? - НУЖЕН")
                                print(" - установить ROPA_EURO_TIGER_4_V00.sh ?")
                                print(" - установить ROPA_EURO_TIGER_4_V0-10s.sh ?")
                                print(" - установить ROPA_EURO_TIGER_4_VF1-adv.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_VF0-adv')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_V00')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_V0-10s')
                                install_can_4 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_VF1-adv')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить TIGER_4_VF0-adv", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить TIGER_4_V00",
                                                                                       callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(text="установить TIGER_4_V0-10s",
                                                                                       callback_data=install_can_3)
                                callback_button_install_4 = types.InlineKeyboardButton(text="установить TIGER_4_VF1-adv",
                                                                                       callback_data=install_can_4)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)
                                keyboard.add(callback_button_install_4)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить ROPA_EURO_TIGER_4_VF0-adv.sh ? - НУЖЕН")
                                print(" - установить ROPA_EURO_TIGER_4_V00.sh ?")
                                print(" - установить ROPA_EURO_TIGER_4_V0-10s.sh ?")
                                print(" - установить ROPA_EURO_TIGER_4_VF1-adv.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_VF0-adv')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_V00')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_V00')
                                install_can_4 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_VF1-adv')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="установить TIGER_4_VF0-adv",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить TIGER_4_V00",
                                                                                       callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(text="установить TIGER_4_V0-10s",
                                                                                       callback_data=install_can_3)
                                callback_button_install_4 = types.InlineKeyboardButton(text="установить TIGER_4_VF1-adv",
                                                                                       callback_data=install_can_4)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)
                                keyboard.add(callback_button_install_4)

                        # TIGER_4_VF1 or TIGER_4_VF1_10s or TIGER_4_VF1-adv
                        elif config_version_from_table == 'TIGER_4_VF1' or config_version_from_table == 'TIGER_4_VF1_10s' or config_version_from_table == 'TIGER_4_VF1-adv':
                            print('# config: ', config_version_from_table)
                            if 'ROPA_EURO_TIGER_4_VF1-adv' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить ROPA_EURO_TIGER_4_VF1-adv ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_VF1-adv')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_V00')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_V00')
                                install_can_4 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_VF0-adv')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить TIGER_4_VF1-adv", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить TIGER_4_V00",
                                                                                       callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(text="установить TIGER_4_V0-10s",
                                                                                       callback_data=install_can_3)
                                callback_button_install_4 = types.InlineKeyboardButton(text="установить TIGER_4_VF0-adv",
                                                                                       callback_data=install_can_4)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)
                                keyboard.add(callback_button_install_4)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить ROPA_EURO_TIGER_4_VF1-adv ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_VF1-adv')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_V00')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_V00')
                                install_can_4 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'TIGER_4_VF0-adv')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="установить TIGER_4_VF1-adv",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить TIGER_4_V00",
                                                                                       callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(text="установить TIGER_4_V0-10s",
                                                                                       callback_data=install_can_3)
                                callback_button_install_4 = types.InlineKeyboardButton(text="установить TIGER_4_VF0-adv",
                                                                                       callback_data=install_can_4)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)
                                keyboard.add(callback_button_install_4)
                        # Tiger_6_V00
                        elif config_version_from_table == 'Tiger_6_V00':
                            print('# config: ', config_version_from_table)
                            if 'ROPA_EURO_Tiger_6_V00' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить ROPA_EURO_Tiger_6_V00.sh ? - НУЖНО")
                                print(" - установить ROPA_EURO_Tiger_6_V0.sh ?")
                                print(" - установить ROPA_EURO_Tiger_6_V1.sh ?")
                                print(" - установить ROPA_EURO_Tiger_6_V2022.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V00')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V0')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V1')
                                install_can_4 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V2022')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="переустановить Tiger_6_V00",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить Tiger_6_V0",
                                                                                       callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(text="установить Tiger_6_V1",
                                                                                       callback_data=install_can_3)
                                callback_button_install_4 = types.InlineKeyboardButton(text="установить Tiger_6_V2022",
                                                                                       callback_data=install_can_4)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)
                                keyboard.add(callback_button_install_4)


                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить ROPA_EURO_Tiger_6_V00.sh ? - НУЖНО")
                                print(" - установить ROPA_EURO_Tiger_6_V0.sh ?")
                                print(" - установить ROPA_EURO_Tiger_6_V1.sh ?")
                                print(" - установить ROPA_EURO_Tiger_6_V2022.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V00')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V0')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V1')
                                install_can_4 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V2022')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="установить Tiger_6_V00",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить Tiger_6_V0",
                                                                                       callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(text="установить Tiger_6_V1",
                                                                                       callback_data=install_can_3)
                                callback_button_install_4 = types.InlineKeyboardButton(text="установить Tiger_6_V2022",
                                                                                       callback_data=install_can_4)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)
                                keyboard.add(callback_button_install_4)

                        # Tiger_6_V2022
                        elif config_version_from_table == 'Tiger_6_V2022':
                            print('# config: ', config_version_from_table)
                            if 'ROPA_EURO_Tiger_6_V2022' or 'ROPA euro-Tiger 6 V2022' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить ROPA_EURO_Tiger_6_V2022.sh ? - НУЖНО")
                                print(" - установить ROPA_EURO_Tiger_6_V00.sh ?")
                                print(" - установить ROPA_EURO_Tiger_6_V0.sh ?")
                                print(" - установить ROPA_EURO_Tiger_6_V1.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V2022')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V0')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V1')
                                install_can_4 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V00')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="переустановить Tiger_6_V2022",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить Tiger_6_V0",
                                                                                       callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(text="установить Tiger_6_V1",
                                                                                       callback_data=install_can_3)
                                callback_button_install_4 = types.InlineKeyboardButton(text="установить Tiger_6_V00",
                                                                                       callback_data=install_can_4)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)
                                keyboard.add(callback_button_install_4)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить ROPA_EURO_Tiger_6_V00.sh ?")
                                print(" - установить ROPA_EURO_Tiger_6_V0.sh ?")
                                print(" - установить ROPA_EURO_Tiger_6_V1.sh ?")
                                print(" - установить ROPA_EURO_Tiger_6_V2022.sh ? - НУЖНО")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V2022')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V0')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V1')
                                install_can_4 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'Tiger_6_V00')
                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="установить Tiger_6_V2022",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить Tiger_6_V0",
                                                                                       callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(text="установить Tiger_6_V1",
                                                                                       callback_data=install_can_3)
                                callback_button_install_4 = types.InlineKeyboardButton(text="установить Tiger_6_V00",
                                                                                       callback_data=install_can_4)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)
                                keyboard.add(callback_button_install_4)

                        # V00 = MAXTRON_620_V00.sh
                        elif config_version_from_table == 'V00':
                            print('# config: ', config_version_from_table)
                            if 'MAXTRON_620_V00' or 'MAXTRON 620 V00' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить MAXTRON_620_V00.sh ? - НУЖНО")
                                print(" - установить MAXTRON_620_V0.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAXTRON_620_V00')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAXTRON_620_V0')

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить MAXTRON_620_V00", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить MAXTRON_620_V0",
                                                                                       callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить MAXTRON_620_V00.sh ? - НУЖНО")
                                print(" - установить MAXTRON_620_V0.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAXTRON_620_V00')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'MAXTRON_620_V0')

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(text="установить MAXTRON_620_V00",
                                                                                       callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(text="установить MAXTRON_620_V0",
                                                                                       callback_data=install_can_2)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)

                        # V21-01-adv-noload = MAUS_V21-01-adv-noload.sh
                        elif config_version_from_table == 'V21-01-adv-noload':
                            print('# config: ', config_version_from_table)
                            if 'MAUS_V21-01-adv-noload' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить MAUS_V21-01-adv-noload.sh ? - НУЖНО")
                                print(" - установить MAUS_VF0-adv-noloader-10s.sh ?")
                                print(" - установить MAUS_VF00-adv-noloader-10s.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'V21-01-adv-noload')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF0-adv-noloader')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF00-adv-noloader')

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить MAUS_V21-01-adv-noload", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF0-adv-noloader-10s", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF00-adv-noloader-10s", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить MAUS_V21-01-adv-noload.sh ? - НУЖНО")
                                print(" - установить MAUS_VF0-adv-noloader-10s.sh ?")
                                print(" - установить MAUS_VF00-adv-noloader-10s.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'V21-01-adv-noload')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF0-adv-noloader')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF00-adv-noloader')

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить MAUS_V21-01-adv-noload", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF0-adv-noloader-10s", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF00-adv-noloader-10s", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                        # VF0-adv-noloader = MAUS_VF0-adv-noloader-10s.sh
                        elif config_version_from_table == 'VF0-adv-noloader':
                            print('# config: ', config_version_from_table)
                            if 'MAUS_VF0-adv-noloader-10s' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - переустановить MAUS_VF0-adv-noloader-10s.sh ? - НУЖНО")
                                print(" - установить MAUS_VF00-adv-noloader-10s.sh ?")
                                print(" - установить MAUS_V21-01-adv-noload.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF0-adv-noloader')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'V21-01-adv-noload')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF00-adv-noloader')

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить MAUS_VF0-adv-noloader-10s", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_V21-01-adv-noload", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF00-adv-noloader-10s", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить MAUS_VF0-adv-noloader-10s.sh ? - НУЖНО")
                                print(" - установить MAUS_VF00-adv-noloader-10s.sh ?")
                                print(" - установить MAUS_V21-01-adv-noload.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF0-adv-noloader')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'V21-01-adv-noload')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF00-adv-noloader')

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF0-adv-noloader-10s", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_V21-01-adv-noload", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF00-adv-noloader-10s", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                        # VF00-adv-noloader = MAUS_VF00-adv-noloader-10s.sh
                        elif config_version_from_table == 'VF00-adv-noloader':
                            print('# config: ', config_version_from_table)
                            if 'MAUS_VF00-adv-noloader-10s' in vehicle_type_wirenboard:
                                print(' - ура, равно! ', vehicle_type_wirenboard, ' == ', config_version_from_table)
                                print(" - установить MAUS_VF0-adv-noloader-10s.sh ?")
                                print(" - переустановить MAUS_VF00-adv-noloader-10s.sh ? - НУЖНО")
                                print(" - установить MAUS_V21-01-adv-noload.sh ?")

                                can_result_config = f'\n - конфиг CAN установлен согласно таблице.'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF00-adv-noloader')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'V21-01-adv-noload')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF0-adv-noloader')

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="переустановить MAUS_VF00-adv-noloader-10s", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_V21-01-adv-noload", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF0-adv-noloader-10s", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                            else:
                                print(' - не равно ... ', vehicle_type_wirenboard, ' != ', config_version_from_table)
                                print(" - установить MAUS_VF0-adv-noloader-10s.sh ?")
                                print(" - установить MAUS_VF00-adv-noloader-10s.sh ? - НУЖНО")
                                print(" - установить MAUS_V21-01-adv-noload.sh ?")

                                can_result_config = f'\n - конфиг CAN не ок ...\nустановлено|надо:\n{vehicle_type_wirenboard} | {config_version_from_table}'

                                install_can_1 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF00-adv-noloader')
                                install_can_2 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'V21-01-adv-noload')
                                install_can_3 = str('can_inst ' + ip + ' ' + reg_num + ' ' + 'VF0-adv-noloader')

                                keyboard = types.InlineKeyboardMarkup()
                                callback_button_install_1 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF00-adv-noloader-10s", callback_data=install_can_1)
                                callback_button_install_2 = types.InlineKeyboardButton(
                                    text="установить MAUS_V21-01-adv-noload", callback_data=install_can_2)
                                callback_button_install_3 = types.InlineKeyboardButton(
                                    text="установить MAUS_VF0-adv-noloader-10s", callback_data=install_can_3)
                                keyboard.add(callback_button_install_1)
                                keyboard.add(callback_button_install_2)
                                keyboard.add(callback_button_install_3)

                        else:
                            can_result_config = f'\n - конфиг CAN ...\n - хня какая-то, нет такого условия.'
                            print('\n - нет условия - \n')

                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                              text=f'{result_tg}\nданные из wirenboard:\nconfig: {vehicle_type_wirenboard}\nservice: {status_service_can_status} | {status_service_can_status_2} | {time_service_can_status}\ntimeout: {timedout_in_line}\n{can_result_config}{can_result_timeout_and_status}',
                                              reply_markup=keyboard)

                    elif can_read_wirenboard == TimeoutError:
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{result_tg}\nданные из wirenboard:\n - TimeoutError!', reply_markup=keyboard)
                except AttributeError as attr:
                    print('AttributeError: ', attr.with_traceback())
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{result_tg}\nданные из wirenboard:\n - AttributeError:\n{attr.with_traceback()}', reply_markup=keyboard)
                except Exception as e:
                    print('Exception: ', e.with_traceback())
                    keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                    bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                          text=f'{result_tg}\nданные из wirenboard:\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)

    # установка конфига кан
    elif 'can_inst' in call.data:
        input_tg = call.data.split()
        ip = input_tg[1]
        reg_num = input_tg[2]
        value_for_command_with_version_config_input = input_tg[3]
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        if value_for_command_with_version_config_input == 'Felis_2_V2020':
            value_for_command_with_version_config_output = "'Holmer Terra Felis 2 V2020.sh'"
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'Felis_2_V2021':
            value_for_command_with_version_config_output = "'Holmer Terra Felis 2 V2021.sh'"
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'MAUS_VF0-adv-noloader-10s' or value_for_command_with_version_config_input == 'VF0-adv-noloader':
            value_for_command_with_version_config_output = 'MAUS_VF0-adv-noloader-10s.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'MAUS_VF00-adv-noloader-10s' or value_for_command_with_version_config_input == 'VF00-adv-noloader':
            value_for_command_with_version_config_output = 'MAUS_VF00-adv-noloader-10s.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'MAUS_V21-01-adv-noload' or value_for_command_with_version_config_input == 'V21-01-adv-noload':
            value_for_command_with_version_config_output = 'MAUS_V21-01-adv-noload.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'MAUS_9093-adv-noloader-10s':
            value_for_command_with_version_config_output = 'MAUS_9093-adv-noloader-10s.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'T2_LOADER_V0':
            value_for_command_with_version_config_output = "'Holmer Terra Dos T2 LOADER V0.sh'"
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'T3_V0':
            value_for_command_with_version_config_output = "'Holmer Terra Dos T3 V0.sh'"
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'T3_V1':
            value_for_command_with_version_config_output = "'Holmer Terra Dos T3 V1.sh'"
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'T3_V2':
            value_for_command_with_version_config_output = "'Holmer Terra Dos T3 V2.sh'"
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'T4-40_VF0-10s':
            value_for_command_with_version_config_output = 'Holmer_Terra_Dos_T4-40_VF0-10s.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'T4-40_VF0-adv-10s':
            value_for_command_with_version_config_output = 'Holmer_Terra_Dos_T4-40_VF0-adv-10s.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'TIGER_4_VF0-adv':
            value_for_command_with_version_config_output = 'ROPA_EURO_TIGER_4_VF0-adv.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'TIGER_4_V0-10s':
            value_for_command_with_version_config_output = 'ROPA_EURO_TIGER_4_V0-10s.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'TIGER_4_V00':
            value_for_command_with_version_config_output = 'ROPA_EURO_TIGER_4_V00.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'TIGER_4_VF1-adv':
            value_for_command_with_version_config_output = 'ROPA_EURO_TIGER_4_VF1-adv.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'Tiger_6_V00':
            value_for_command_with_version_config_output = 'ROPA_EURO_Tiger_6_V00.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'Tiger_6_V0':
            value_for_command_with_version_config_output = 'ROPA_EURO_Tiger_6_V0.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'Tiger_6_V1':
            value_for_command_with_version_config_output = 'ROPA_EURO_Tiger_6_V1.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'Tiger_6_V2022':
            value_for_command_with_version_config_output = 'ROPA_EURO_Tiger_6_V2022.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'MAXTRON_620_V00':
            value_for_command_with_version_config_output = 'MAXTRON_620_V00.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        elif value_for_command_with_version_config_input == 'MAXTRON_620_V0':
            value_for_command_with_version_config_output = 'MAXTRON_620_V0.sh'
            print('\n - устанавливаем конфиг: ', value_for_command_with_version_config_output, '\n')
        else:
            value_for_command_with_version_config_output = 'Error'
            print('\n - ', value_for_command_with_version_config_output, ', не понятный input: ',
                  value_for_command_with_version_config_input, '\n')


        bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                              text=f'{call.message.text}\n - устанавливаю конфиг {value_for_command_with_version_config_output} на {ip} ...')
        command = f"""rm install_can_v3.tar.gz; rm -rf CAN; wget http://213.208.180.57/vbjdvbdsddds/install_can_v3.tar.gz; mkdir CAN; tar -xf install_can_v3.tar.gz -C /root/CAN; cd CAN/install_can_v3;./{value_for_command_with_version_config_output}"""
        print('\n - ', ip, ' | ', command)
        threadname = f'check_can_read {ip} | {call.message.chat.username}'
        thread = ThreadWithResult(target=ssh_connect, name=threadname,
                                  args=[ip, config.wirenboard_username, config.wirenboard_password, command, 60, 60])
        thread.start()
        thread.join()

        try:
            can_write_wirenboard = thread.result
            print()
            print(can_write_wirenboard)
            print()

            if len(can_write_wirenboard) > 0:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n - конфиг {value_for_command_with_version_config_output} установлен.',
                                      reply_markup=keyboard)
            elif can_write_wirenboard == TimeoutError:
                keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                      text=f'{call.message.text}\n - TimeoutError!', reply_markup=keyboard)
        except AttributeError as attr:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n - AttributeError:\n{attr.with_traceback()}', reply_markup=keyboard)
        except Exception as e:
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id,
                                  text=f'{call.message.text}\n - Exception:\n{e.with_traceback()}', reply_markup=keyboard)

    # кнопка - соседи
    elif 'function_get_neighbors' in call.data:
        input_data = call.data.split()
        message = call.message.text
        ip = input_data[1]
        reg_num = input_data[2]
        len_neigs_data = len_neighbors(reg_num)
        function_ping = str('function_ping ' + ip + ' ' + reg_num)
        sleep = str('sleep ' + ip + ' ' + reg_num)
        keyboard = types.InlineKeyboardMarkup()
        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')

        if len_neigs_data[0] == 0 and len_neigs_data[1] == 0:
            len_neigs = '0'
            len_his_neigs = '0'
            result = ' - никого не видит.\n - никто не видит.'
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{message}\n\n{result}', reply_markup=keyboard)

        elif len_neigs_data[0] != 0 and len_neigs_data[1] != 0:
            len_neigs = len_neigs_data[0]
            len_his_neigs = len_neigs_data[1]
            data_hosts = []
            data_neigs = []
            difference = []

            for x in len_neigs:
                host = x[0] + ' ' + x[1] + ' ' + x[2]
                data_hosts.append(host)
            for y in len_his_neigs:
                neigh = y[0] + ' ' + y[1] + ' ' + y[2]
                data_neigs.append(neigh)

            result_host = '\n'.join(data_hosts)
            result_neigs = '\n'.join(data_neigs)

            first_tuple_list = [tuple(lst) for lst in len_neigs]
            second_tuple_list = [tuple(lst) for lst in len_his_neigs]
            first_set = set(first_tuple_list)
            second_set = set(second_tuple_list)
            result_difference = second_set.symmetric_difference(first_set)
            for line in result_difference:
                host_line = line[0] + ' ' + line[1] + ' ' + line[2]
                difference.append(host_line)
            result_tg_difference = '\n'.join(difference)

            if result_difference != set():
                tg_diff_result = f'\n\n - разница: \n{result_tg_difference}'
            elif result_difference == set():
                tg_diff_result = f'\n\n - разницы нет.'

            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{message}\n\n - он видит:\n{result_host}\n\n - его видят:\n{result_neigs}{tg_diff_result}', reply_markup=keyboard)

        elif len_neigs_data[0] == 0 and len_neigs_data[1] != 0:
            len_neigs = ' - никого не видит.'
            len_his_neigs = len_neigs_data[1]
            data_neigs = []
            for y in len_his_neigs:
                neigh = y[0] + ' ' + y[1] + ' ' + y[2]
                data_neigs.append(neigh)
            result_neigs = '\n'.join(data_neigs)
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{message}\n\n - он видит:\n{len_neigs}\n\n - его видят:\n{result_neigs}', reply_markup=keyboard)

        elif len_neigs_data[0] != 0 and len_neigs_data[1] == 0:
            len_neigs = len_neigs_data[0]
            len_his_neigs = ' - никто не видит.'
            data_hosts = []
            for x in len_neigs:
                host = x[0] + ' ' + x[1] + ' ' + x[2]
                data_hosts.append(host)
            result_host = '\n'.join(data_hosts)
            keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=f'{message}\n\n - он видит:\n{result_host}\n\n - его видят:\n{len_his_neigs}', reply_markup=keyboard)



# ЭКСЕЛЬ С ЗАЯВКАМИ ИЗ ХУЕБЕКСА
@bot.message_handler(content_types=['document'])
def handle_docs(message):
    if message.from_user.username in config.users or config.admins:
        if thisFile == config.this_is_server:
            bot.send_message(message.chat.id, 'на сервере не работает пандас. данный функционал отключен.')
        else:
            print('name document: ', message.document.file_name)
            file_info = bot.get_file(message.document.file_id)
            downloaded_file = bot.download_file(file_info.file_path)
            src = config.temp_dir + message.document.file_name
            with open(src, 'wb') as new_file:
                new_file.write(downloaded_file)
            excel_data = pandas.read_excel(src, sheet_name='Заявки', usecols=['AssetName', 'Notes'])
            list = excel_data.values.tolist()
            for line in list[2:]:
                ticket_reg_num = line[1]
                ticket_theme = line[0]

                def neighbors_host():
                    with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
                        data = file.readlines()
                        for line in data:
                            all_result_line = line.split()
                            tachka = all_result_line[0:3]
                            if ticket_reg_num in str(tachka):
                                result = tachka
                                return result

                def neighbors_broadcast():
                    with open(config.file_neighbors_txt, 'r', encoding='utf-8') as file:
                        data = file.readlines()
                        for line in data:
                            all_result_line = line.split()
                            tachka = all_result_line[0:3]
                            neig = all_result_line[3:]

                            neig1 = neig[0:4]
                            neig2 = neig[4:8]
                            neig3 = neig[8:12]
                            neig4 = neig[12:16]
                            neig5 = neig[16:20]

                            soseds = []

                            if ticket_reg_num in str(neig):
                                if ticket_reg_num in str(neig1):
                                    print('--- сосед 1: ', tachka + neig1)
                                    # soseds.append(tachka + neig1)
                                elif ticket_reg_num in str(neig2):
                                    print('--- сосед 2: ', tachka + neig2)
                                    # soseds.append(tachka + neig2)
                                elif ticket_reg_num in str(neig3):
                                    print('--- сосед 3: ', tachka + neig3)
                                    # soseds.append(tachka + neig3)
                                elif ticket_reg_num in str(neig4):
                                    print('--- сосед 4: ', tachka + neig4)
                                    # soseds.append(tachka + neig4)
                                elif ticket_reg_num in str(neig5):
                                    print('--- сосед 5: ', tachka + neig5)
                                    # soseds.append(tachka + neig5)
                        print()
                        # print('--- soseds --- ', soseds)

                def fread200():
                    with open(config.file_200_txt, 'r', encoding='utf8') as fopen200:
                        fread200_file = fopen200.readlines()
                        for line in fread200_file:
                            if ticket_reg_num in line:
                                # print('!! найдено в 200! ', line)
                                return line

                host = neighbors_host()
                b_host = neighbors_broadcast()
                fread_return_200 = fread200()
                print(ticket_theme, '|', ticket_reg_num)
                print('file host: ', host)
                print('file b_host: ', b_host)
                print('file fread_return: ', fread_return_200)
                print()

                function_watch = str('function_watch ' + ticket_reg_num)

                if host == None and b_host == None and fread_return_200 == None:
                    sleep = str('sleep ' + 'None' + ' ' + ticket_reg_num)
                    var = ticket_reg_num
                    info = str(ticket_theme + ' | ' + ticket_reg_num)
                    threadname = str('слежу за ' + ticket_reg_num + ' | ' + message.from_user.username)
                    scan_neighbors_auto_thread = threading.Thread(target=auto_watch_function, name=threadname,
                                                                  args=[var, message, info])
                    scan_neighbors_auto_thread.start()
                    bot.send_message(message.chat.id,
                                     f'Тикет: {ticket_theme} | {ticket_reg_num}\n - слежу за {ticket_reg_num}.')

                elif host:
                    if fread_return_200 == None:
                        ip_198 = host[0]
                        reg_num_198 = host[1]
                        dev_id_198 = host[2]
                        function_ping = str('function_ping ' + ip_198 + ' ' + reg_num_198)
                        sleep = str('sleep ' + ip_198 + ' ' + reg_num_198)
                        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                        keyboard = types.InlineKeyboardMarkup()
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_198} {reg_num_198} {dev_id_198}',
                                         reply_markup=keyboard)
                    elif fread_return_200:
                        ip_198 = host[0]
                        reg_num_198 = host[1]
                        dev_id_198 = host[2]
                        function_ping = str('function_ping ' + ip_198 + ' ' + reg_num_198)
                        sleep = str('sleep ' + ip_198 + ' ' + reg_num_198)
                        callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                        callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                        callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                        keyboard = types.InlineKeyboardMarkup()
                        keyboard.add(callback_button_ping, callback_button_sleep, callback_button_close)
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_198} {reg_num_198} {dev_id_198}\n{fread_return_200}',
                                         reply_markup=keyboard)
                elif b_host:
                    # soseds = []
                    if fread_return_200 == None:
                        print('--- соседи: ', b_host)
                        # tachka = b_host[0:3]

                        bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{b_host}')

                        # bot.send_message(message.chat.id, f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{b_host[0]} {b_host[1]} {b_host[2]}\n{b_host[7]} | {b_host[4]} {b_host[5]} {b_host[6]}')

                    elif fread_return_200:
                        print('--- соседи: ', b_host)
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{b_host}\n\n{fread_return_200}')

                elif fread_return_200:
                    data = fread_return_200.split()
                    ip_200 = data[0]
                    reg_num_200 = data[1]
                    dev_id_200 = data[2]
                    threadname = f'ping {ip_200} | {message.from_user.username}'
                    thread_ping = ThreadWithResult(target=ping_function, name=threadname, args=[message, ip_200])
                    thread_ping.start()
                    thread_ping.join()
                    # result_output = thread.result
                    print('thread.result: ', thread_ping.result)
                    function_ping = str('function_ping ' + ip_200 + ' ' + reg_num_200)
                    sleep = str('sleep ' + ip_200 + ' ' + reg_num_200)
                    callback_button_watch = types.InlineKeyboardButton(text="следить", callback_data=function_watch)
                    callback_button_ping = types.InlineKeyboardButton(text="пинг", callback_data=function_ping)
                    callback_button_sleep = types.InlineKeyboardButton(text="отложить", callback_data=sleep)
                    callback_button_close = types.InlineKeyboardButton(text="закрыть", callback_data='close')
                    keyboard = types.InlineKeyboardMarkup()

                    if thread_ping.result == 0:
                        keyboard.add(callback_button_ping, callback_button_watch, callback_button_sleep,
                                     callback_button_close)
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_200} {reg_num_200} {dev_id_200}\n - ping {ip_200} - ok!',
                                         reply_markup=keyboard)
                    else:
                        var = ticket_reg_num
                        info = str(ticket_theme + ' | ' + ticket_reg_num)
                        threadname = str('слежу за ' + ticket_reg_num + ' | ' + message.from_user.username)
                        scan_neighbors_auto_thread = threading.Thread(target=auto_watch_function, name=threadname,
                                                                      args=[var, message, info])
                        scan_neighbors_auto_thread.start()
                        bot.send_message(message.chat.id,
                                         f'Тикет: {ticket_theme} | {ticket_reg_num}\n\n{ip_200} {reg_num_200} {dev_id_200}\n - ping {ip_200} don`t ok ...\n - слежу за {ticket_reg_num}.')

    else:
        bot.send_message(message.chat.id, f'у {message.from_user.username} нет доступа')

# RUN
if thisFile == config.this_is_home:
    os.system("""sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'""")
    ping_server = os.system("ping -s 32 -c 1 " + config.server_ip)
    if ping_server == 0:
        pass
    elif ping_server != 0:
        connect_vpn = os.system("sudo nmcli c up VPN_ABM")
    command = './add_iptables.sh'
    add_iptables = threading.Thread(target=ssh_connect, name='add_iptables.sh',
                                    args=[config.server_ip, config.server_username, config.server_password, command, 30, 30])
    add_iptables.start()
    add_iptables.join()
    scan_neighbors_auto_thread = threading.Thread(target=scan_neighbors_auto, name='scanner', args=[])
    scan_neighbors_auto_thread.start()
    os.system(f'sudo rm {config.temp_dir_home}*.xlsx; sudo rm {config.temp_dir_home}*.key; sudo rm {config.temp_dir_home}*.crt')
elif thisFile == config.this_is_server:
    scan_neighbors_auto_thread = threading.Thread(target=scan_neighbors_auto, name='scanner', args=[])
    scan_neighbors_auto_thread.start()
    os.system(f'rm {config.temp_dir_server}*.key; rm {config.temp_dir_server}*.crt')
elif thisFile == config.this_is_docker:
    scan_neighbors_auto_thread = threading.Thread(target=scan_neighbors_auto, name='scanner', args=[])
    scan_neighbors_auto_thread.start()
else:
    print(' --- !!! ---', thisFile, ' --- this is test version ---')

def telegram_polling():
    try:
        bot.polling(none_stop=True)
    except:
        traceback_error_string = traceback.format_exc()
        print("\r\n\r\n" + time.strftime(
            "%c") + "\r\n<<ERROR polling>>\r\n" + traceback_error_string + "\r\n<<ERROR polling>>")
        with open(config.file_error_log, "a") as myfile:
            myfile.write("\r\n\r\n" + time.strftime(
                "%c") + "\r\n<<ERROR polling>>\r\n" + traceback_error_string + "\r\n<<ERROR polling>>")
        bot.stop_polling()
        time.sleep(3)
        telegram_polling()

telegram_polling()
