from datetime import datetime

class LogEntry:
    def __init__(self, timestamp, level, session_id, user, client_ip, module, message):
        self.timestamp = timestamp
        self.level = level
        self.session_id = session_id
        self.user = user
        self.client_ip = client_ip
        self.module = module
        self.message = message

    def __str__(self):
        return "["+str(self.timestamp)+"] ["+self.level+"] ["+ self.module+"] "+self.message


def parse_line(line):
    parts = line.split("] ", 6)
    if len(parts) != 7:
        return None
    
    timestamp_text = parts[0].lstrip("[")
    level = parts[1].lstrip("[")
    session_id = parts[2].lstrip("[")
    user = parts[3].lstrip("[")
    client_ip = parts[4].lstrip("[")
    module = parts[5].lstrip("[")
    message = parts[6]
    if message.startswith("- "):
        message = message[2:]

    try:
        timestamp = datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return LogEntry(timestamp, level.upper(), session_id, user, client_ip, module.upper(), message)

def get_query_type(message):
    msg_upper = message.upper()
    for keyword in ["SELECT", "INSERT", "UPDATE", "DELETE"]:
        if keyword in msg_upper:
            return keyword
    return "UNKNOWN"

def get_execution_time(message):
    lower_msg = message.lower()
    if "execution time" in lower_msg:
        index = lower_msg.find("execution time")
        return message[index + len("execution time"):].strip()
    return "N/A"

def get_amount(message):
    if "$" not in message:
        return None
    index = message.find("$")
    rest = message[index + 1:]
    amount_text = ""
    for ch in rest:
        if ch.isdigit() or ch == ".":
            amount_text += ch
        elif ch == ",":
            continue
        else:
            break
    if amount_text == "":
        return None
    return float(amount_text)


def get_attempted_user(message, default_user):
    if "for user " in message:
        after = message.split("for user ")[1]
        return after.split()[0]
    return default_user