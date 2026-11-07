
import psutil


def collect_processes():

    processes = []

    for process in psutil.process_iter(
        ['pid', 'ppid', 'name', 'exe', 'username']
    ):

        try:
            process_info = process.info

            processes.append({
                "pid": process_info["pid"],
                "ppid": process_info["ppid"],
                "name": process_info["name"],
                "path": process_info["exe"],
                "username": process_info["username"]
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


if __name__ == "__main__":

    all_processes = collect_processes()

    print("\n===== PROCESS MONITOR =====")

    for process in all_processes:
        print(process)

    print("\nTotal Processes:", len(all_processes))
