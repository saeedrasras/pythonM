import sys
from reports import LogAnalyzer
from cli import run_report, interactive_menu

def main():
    log_file = "bank_server.log"
    report_number = None
    username = None
    output_file = None

    if len(sys.argv) >= 2:
        log_file = sys.argv[1]

    if len(sys.argv) >= 3:
        try:
            report_number = int(sys.argv[2])
        except ValueError:
            print("The report number must be a number between 1 and 9. Opening the menu instead.")
            report_number = None

    if len(sys.argv) >= 4 and sys.argv[3].lower() != "none":
        username = sys.argv[3]

    if len(sys.argv) >= 5:
        output_file = sys.argv[4]

    analyzer = LogAnalyzer(log_file, output_file)
    analyzer.load_logs()

    if report_number is not None:
        run_report(analyzer, report_number, username)
    else:
        interactive_menu(analyzer)
