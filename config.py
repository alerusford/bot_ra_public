TOKEN = ''
TOKEN_SERVER = ''

users = ''
admins = ''
wirenboard_username = ""
wirenboard_password = ""
server_ip = ""
server_username = ''
server_password = ''
tagpack_spreadsheet_id = ''
broadcast_spreadsheet_id = ''
can_table = ''
time_sleep = 300 # отложить
time_scan_neighbors = 300 #300 # время между сканированием
time_scan_neighbors_nigth = 900 # время между сканированием ночью
times_night = ['5', '4', '3', '2', '1', '00', '23', '22', '21', '20'] # ночные часы
time_ping = 120 # время между пингами
time_watch = 150 # 150 # время между повторами отлеживания
time_setrecursionlimit = 300  # 300 ~ 12 часов    # 205 раза watch в 8 часах # 288 раз wa1tch в 12 часах | 24 watch в 1 часе, при time_watch = 150

hubex_service_token = ''
hubex_time_parser = 60
hubex_while_close = 720 # повторов,  если парсим каждые 60 секунд и 12 часов смена

# docker config
this_is_docker = ''
temp_dir_docker = ''
file_neighbors_txt_docker = ''
file_200_txt_docker = ''
file_error_log_docker = ''
credentials_json_for_google_docker = ''

# home config
this_is_home = ''
nmap_py = 'neighbors.py'
temp_dir_home = ''
file_neighbors_txt_home = ''
file_200_txt_home = ''
file_error_log_home = ''
credentials_json_for_google_home = ''

# server config
this_is_server = ''
temp_dir_server = ''
file_neighbors_txt_server = ''
file_200_txt_server = ''
file_error_log_server = ''
credentials_json_for_google_server = ''
