from flask import Flask
import apache_log_parser
import re
import pygeoip
from flask import jsonify

line_parser = apache_log_parser.make_parser("%t %a")
app = Flask(__name__)
logfileglobal = "C:\\Users\\5559-650124\\Downloads\\CTF1\\CTF1.log"
geodata='C://Users//5559-650124//PycharmProjects//test//static//GeoLiteCity.dat'
IP_PATTERN = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'


@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/getuniqueaddress')
def getUnique_Address():
    return jsonify(get_unique_ips(logfileglobal))


@app.route('/getfileinclusionattacks')
def getFileInclusion():
    return jsonify(get_file_inclusion(logfileglobal))


@app.route('/getsqliattacks')
def getSqliteAttacks():
    return jsonify(get_sql_injections(logfileglobal))


@app.route('/getwebshellattacks')
def getwebshellAttacks():
    return jsonify(get_web_shells_attack(logfileglobal))


@app.route('/getactivitiesperip')
def getactivities_per_ip():
    return jsonify(activities_per_ip(logfileglobal))



def get_web_shells_attack(log_file):
    """
    Read log file and return all detected web shells attack.
    """
    fileinclusion = []
    with open(log_file) as logs:
        for line in logs:
            if 'cmd=' in line:
                regex_match = construct_log_regex().match(str(line))
                if regex_match:
                    jsond = convert_parsed_tuple_to_dictionary(
                        regex_match.groups())
                    fileinclusion.append(jsond)
    return str(fileinclusion)


def get_file_inclusion(log_file):
    """
    Read log file and return all remote file inclusion activities
    """
    terms = ['?file', 'file=']
    fileinclusion = []
    with open(log_file) as logs:
        for line in logs:
            for term in terms:
                if term in line:
                    regex_match = construct_log_regex().match(str(line))
                    if regex_match:
                        jsond = convert_parsed_tuple_to_dictionary(
                            regex_match.groups())
                    fileinclusion.append(jsond)

    return str(fileinclusion)


def get_sql_injections(log_file):
    """
    Read log file and return all sql injection activities
    """
    sqli = ['union+', 'union*', 'system\(', 'eval(', 'group_concat',
            'column_name', 'order by', 'insert into', 'SELECT', 'load_file', 'concat',
            '@@version']
    result = []
    with open(log_file) as logs:
        for line in logs:
            for term in sqli:
                if term in line:
                    regex_match = construct_log_regex().match(str(line))
                    if regex_match:
                        jsond = convert_parsed_tuple_to_dictionary(
                            regex_match.groups())
                    result.append(jsond)
    return str(result)


def activities_per_ip(log_file):
    """
    Read log file and return all activities per ip
    """
    unique_ips = []
    with open(log_file) as logs:
        for line in logs:
            ips = get_log_ips(line)
            result = []
            for ip in ips:
                regex_match = construct_log_regex().match(str(line))
                if regex_match:
                    jsond = convert_parsed_tuple_to_dictionary(
                        regex_match.groups())

                result.append(jsond)
                ip_info = {'ip': ip, 'data': result}

                if ip not in unique_ips:
                    unique_ips.append(ip_info)
            if len(unique_ips) == 10:
                break

    return str(unique_ips)





def get_unique_ips(log_file):
    """
    Read log file and return all unique ip with number of hits and
    country of origin.
    """
    unique_ips = []
    with open(log_file) as logs:
        for line in logs:
            ips = get_log_ips(line)
            for ip in ips:
                # unique ip details
                ip_info = {'ip': ip, 'hits': 1, 'country': None}
                path = geodata
                p = pygeoip.GeoIP(path)

                # get Ip country origin
                addr = ip_info.get('ip')
                match = p.country_code_by_addr(addr)
                if match is not None:
                    ip_info['country'] = match

                # Add number of hits if ip already exist in unique ip list
                # else add it to the unique ip list
                ip_exist = search_dict_in_list(ip, unique_ips)
                if not ip_exist:
                    unique_ips.append(ip_info)
                else:
                    ip_exist['hits'] += 1

            if len(unique_ips) == 20:
                break

    return str(unique_ips)

def search_dict_in_list(ip, arr):
    for item in arr:
        if item['ip'] == ip:
            return item


def is_log_file(log_file):
    if log_file:
        return log_file.split('.')[1] == 'log'


def is_valid_ip(ip):
    if ip:
        return re.match(IP_PATTERN, ip)


def get_log_ips(log):
    ips = []
    if log:
        arr = log.split(' ')
        for item in arr:
            if is_valid_ip(item):
                ips.append(item)
    return ips

def construct_log_regex():
    date_regex = r'([0-9-]+)'
    time_regex = r'([0-9:]+)'
    ip_regex = r'(\d+\.\d+\.\d+\.\d+)'
    http_method_regex = r'(GET|POST|PATCH|PUT|DELETE|HEAD|OPTIONS)'
    url_path_regex = r'(/|/[^\s]+)'
    freetext_regex = r'(-|.+)'
    number_regex = r'([0-9]+)'
    word_regex = r'(-|[^\s]+)'
    url_regex = r'(-|http[s]?:.+)'

    return re.compile(
        (
            '^{date}\s{time}\s{server_ip}\s{http_method}\s{url_path}\s'
            '{query_string}\s{server_port}\s{username}\s{client_ip}\s'
            '{user_agent}\s{referer_url}\s{status}\s{substatus}\s'
            '{win_32_status}\s{time_taken}$'
        ).format(
            date=date_regex,
            time=time_regex,
            server_ip=ip_regex,
            http_method=http_method_regex,
            url_path=url_path_regex,
            query_string=freetext_regex,
            server_port=number_regex,
            username=word_regex,
            client_ip=ip_regex,
            user_agent=freetext_regex,
            referer_url=url_regex,
            status=number_regex,
            substatus=number_regex,
            win_32_status=number_regex,
            time_taken=number_regex,
        )
    )


def convert_parsed_tuple_to_dictionary(regex_tuple):
    return {
        'date': regex_tuple[0],
        'time': regex_tuple[1],
        'server_ip': regex_tuple[2],
        'http_method': regex_tuple[3],
        'url_path': regex_tuple[4],
        'query_string': regex_tuple[5],
        'server_port': regex_tuple[6],
        'username': regex_tuple[7],
        'client_ip': regex_tuple[8],
        'user_agent': regex_tuple[9],
        'referer_url': regex_tuple[10],
        'status': regex_tuple[11],
        'substatus': regex_tuple[12],
        'win_32_status': regex_tuple[13],
        'time_taken': regex_tuple[14]
    }



if __name__ == '__main__':
    app.run()
