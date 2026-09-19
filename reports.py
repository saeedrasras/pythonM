from parser import parse_line, get_query_type, get_execution_time, get_amount, get_attempted_user

def write_diagnostic(message):
    diagnostic_file = open("analyzer_diagnostics.log", "a")
    diagnostic_file.write(message + "\n")
    diagnostic_file.close()


class LogAnalyzer:
    def __init__(self, log_file_path, output_file=None):
        self.log_file_path = log_file_path
        self.output_file = output_file
        self.entries = []
        self.malformed_count = 0

    def load_logs(self):
        # try/except for a missing file (Lab 9, section 0.11 Exception Handling).
        try:
            log_file = open(self.log_file_path, "r")
        except FileNotFoundError:
            print("ERROR: could not find log file '" + self.log_file_path + "'.")
            write_diagnostic("Log file not found: " + self.log_file_path)
            return

        for raw_line in log_file:
            line = raw_line.strip()
            if line == "":
                continue

            entry = parse_line(line)
            if entry is None:
                self.malformed_count += 1
                write_diagnostic("Could not parse line: " + line)
            else:
                self.entries.append(entry)

        log_file.close()
        print("Loaded " + str(len(self.entries)) + " valid log entries (" +
              str(self.malformed_count) + " malformed lines skipped).")

    def show(self, text):
        # Prints a report, and also saves it to a file if one was given.
        print(text)
        if self.output_file:
            output = open(self.output_file, "a")
            output.write(text + "\n")
            output.close()

    # 1. Failed Login Report
    def failed_login_report(self):
        counts_by_ip = {}
        counts_by_user = {}
        total = 0

        for entry in self.entries:
            if entry.module == "AUTH" and entry.level == "ERROR" and \
                    "failed login attempt" in entry.message.lower():
                total += 1
                counts_by_ip[entry.client_ip] = counts_by_ip.get(entry.client_ip, 0) + 1

                attempted_user = get_attempted_user(entry.message, entry.user)
                counts_by_user[attempted_user] = counts_by_user.get(attempted_user, 0) + 1

        lines = ["=== Failed Login Report ===",
                 "Total failed login attempts: " + str(total), "",
                 "By client IP address:"]
        for ip in counts_by_ip:
            count = counts_by_ip[ip]
            flag = "  <-- possible brute-force source!" if count >= 3 else ""
            lines.append("  " + ip + ": " + str(count) + " attempt(s)" + flag)

        lines.append("")
        lines.append("By attempted username:")
        for user in counts_by_user:
            lines.append("  " + user + ": " + str(counts_by_user[user]) + " attempt(s)")

        self.show("\n".join(lines))

    # 2. Query Activity Summary
    def query_activity_summary(self):
        total_queries = 0
        type_counts = {}

        for entry in self.entries:
            if entry.module == "QUERY":
                total_queries += 1
                query_type = get_query_type(entry.message)
                type_counts[query_type] = type_counts.get(query_type, 0) + 1

        lines = ["=== Query Activity Summary ===",
                 "Total QUERY events: " + str(total_queries), "",
                 "Breakdown by query type:"]
        for query_type in type_counts:
            lines.append("  " + query_type + ": " + str(type_counts[query_type]))

        self.show("\n".join(lines))

    # 3. Slow Query Detector
    def slow_query_detector(self):
        slow_queries = []
        for entry in self.entries:
            if entry.module == "QUERY" and entry.level == "WARNING" and \
                    "slow" in entry.message.lower():
                slow_queries.append(entry)

        slow_queries.sort(key=lambda e: e.timestamp)

        lines = ["=== Slow Query Detector ===",
                 "Total slow queries found: " + str(len(slow_queries)), ""]
        for entry in slow_queries:
            exec_time = get_execution_time(entry.message)
            lines.append("  [" + str(entry.timestamp) + "] user=" + entry.user +
                         " time=" + exec_time + " -> " + entry.message)

        self.show("\n".join(lines))

    # 4. Transaction Report
    def transaction_report(self):
        deposits = 0
        withdrawals = 0
        declined = 0
        rollbacks = 0
        total_deposited = 0.0
        total_withdrawn = 0.0

        for entry in self.entries:
            if entry.module != "TRANSACTION":
                continue

            msg_lower = entry.message.lower()
            amount = get_amount(entry.message)

            if "declin" in msg_lower:
                declined += 1
            elif "rollback" in msg_lower:
                rollbacks += 1
            elif "deposit" in msg_lower:
                deposits += 1
                if amount is not None:
                    total_deposited += amount
            elif "withdraw" in msg_lower:
                withdrawals += 1
                if amount is not None:
                    total_withdrawn += amount

        lines = [
            "=== Transaction Report ===",
            "Deposits: " + str(deposits) + " (total: $" + str(round(total_deposited, 2)) + ")",
            "Withdrawals: " + str(withdrawals) + " (total: $" + str(round(total_withdrawn, 2)) + ")",
            "Declined transactions: " + str(declined),
            "Rollbacks: " + str(rollbacks),
        ]
        self.show("\n".join(lines))

    # 5. Critical Events Report
    def critical_events_report(self):
        critical_entries = []
        for entry in self.entries:
            if entry.level == "CRITICAL":
                critical_entries.append(entry)
        critical_entries.sort(key=lambda e: e.timestamp)

        lines = ["=== Critical Events Report ===",
                 "Total CRITICAL events: " + str(len(critical_entries)), ""]
        for entry in critical_entries:
            lines.append("  [" + str(entry.timestamp) + "] (" + entry.module + ") " + entry.message)

        self.show("\n".join(lines))

    # 6. User Activity Report
    def user_activity_report(self, username):
        user_entries = []
        for entry in self.entries:
            if entry.user.lower() == username.lower():
                user_entries.append(entry)
        user_entries.sort(key=lambda e: e.timestamp)

        lines = ["=== User Activity Report for '" + username + "' ==="]
        if len(user_entries) == 0:
            lines.append("No activity found for this username.")
        else:
            lines.append("Total actions found: " + str(len(user_entries)))
            lines.append("")
            for entry in user_entries:
                lines.append("  " + str(entry))

        self.show("\n".join(lines))

    # 7. Login/Logout Session Report
    def session_report(self):
        sessions = {}

        auth_entries = []
        for entry in self.entries:
            if entry.module == "AUTH":
                auth_entries.append(entry)
        auth_entries.sort(key=lambda e: e.timestamp)

        for entry in auth_entries:
            if entry.session_id not in sessions:
                sessions[entry.session_id] = {"user": entry.user, "login": None, "logout": None}

            msg_lower = entry.message.lower()
            if "logged in" in msg_lower:
                sessions[entry.session_id]["login"] = entry.timestamp
                sessions[entry.session_id]["user"] = entry.user
            elif "logged out" in msg_lower:
                sessions[entry.session_id]["logout"] = entry.timestamp

        lines = ["=== Login/Logout Session Report ===",
                 "Total sessions found: " + str(len(sessions)), ""]

        for session_id in sessions:
            info = sessions[session_id]
            login_time = info["login"]
            logout_time = info["logout"]

            if login_time is not None and logout_time is not None:
                duration = str(logout_time - login_time)
            elif login_time is not None:
                duration = "N/A (no logout recorded)"
            else:
                duration = "N/A (no login recorded)"

            lines.append("  " + session_id + " | user=" + str(info["user"]) +
                         " | login=" + str(login_time) + " | logout=" + str(logout_time) +
                         " | duration=" + duration)

        self.show("\n".join(lines))

    # 8. Events-per-Hour Report
    def events_per_hour_report(self):
        hour_counts = {}
        for hour in range(24):
            hour_counts[hour] = 0

        for entry in self.entries:
            hour = entry.timestamp.hour
            hour_counts[hour] = hour_counts[hour] + 1

        lines = ["=== Events-per-Hour Report ===", ""]
        for hour in range(24):
            count = hour_counts[hour]
            bar = "*" * count
            hour_text = str(hour).zfill(2)
            lines.append("  " + hour_text + ":00 - " + hour_text + ":59 | " + str(count) + " | " + bar)

        self.show("\n".join(lines))

    # 9. General Log Summary
    def general_summary(self):
        total_lines = len(self.entries) + self.malformed_count

        level_counts = {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
        module_counts = {}

        for entry in self.entries:
            if entry.level in level_counts:
                level_counts[entry.level] += 1
            module_counts[entry.module] = module_counts.get(entry.module, 0) + 1

        busiest_module = "N/A"
        busiest_count = 0
        for module in module_counts:
            if module_counts[module] > busiest_count:
                busiest_module = module
                busiest_count = module_counts[module]

        lines = [
            "=== General Log Summary ===",
            "Total lines in file: " + str(total_lines),
            "Valid parsed entries: " + str(len(self.entries)),
            "Malformed lines skipped: " + str(self.malformed_count),
            "",
            "Events per log level:",
        ]
        for level in ["INFO", "WARNING", "ERROR", "CRITICAL"]:
            lines.append("  " + level + ": " + str(level_counts[level]))

        lines.append("")
        if busiest_module != "N/A":
            lines.append("Busiest module: " + busiest_module + " (" + str(busiest_count) + " events)")
        else:
            lines.append("Busiest module: N/A")

        self.show("\n".join(lines))