REPORT_NAMES = {
    1: "Failed Login Report",
    2: "Query Activity Summary",
    3: "Slow Query Detector",
    4: "Transaction Report",
    5: "Critical Events Report",
    6: "User Activity Report (asks for a username)",
    7: "Login/Logout Session Report",
    8: "Events-per-Hour Report",
    9: "General Log Summary",
}
def run_report(analyzer, choice, username=None):
    if choice == 1:
        analyzer.failed_login_report()
    elif choice == 2:
        analyzer.query_activity_summary()
    elif choice == 3:
        analyzer.slow_query_detector()
    elif choice == 4:
        analyzer.transaction_report()
    elif choice == 5:
        analyzer.critical_events_report()
    elif choice == 6:
        if not username:
            username = input("Enter the username to look up: ").strip()
        analyzer.user_activity_report(username)
    elif choice == 7:
        analyzer.session_report()
    elif choice == 8:
        analyzer.events_per_hour_report()
    elif choice == 9:
        analyzer.general_summary()
    else:
        print("Invalid report number:"+ str(choice))


def interactive_menu(analyzer):
    while True:
        print("\n================ Bank Log Analyzer - Main Menu ================")
        for number in REPORT_NAMES:
            print("  " + str(number) + ". " + REPORT_NAMES[number])
        print("  0. Exit")
        print("=================================================================")
        choice_text = input("Enter your choice (0-9): ").strip()
        if choice_text == "0":
            print("Goodbye!")
            break
        if not choice_text.isdigit() or int(choice_text) not in REPORT_NAMES:
            print("Invalid choice. Please enter a number between 0 and 9.")
            continue
        run_report(analyzer, int(choice_text))