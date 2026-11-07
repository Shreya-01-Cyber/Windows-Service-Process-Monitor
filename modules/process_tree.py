
def build_process_tree(processes):

    process_map = {
        process["pid"]: process
        for process in processes
    }

    process_tree = {}

    for process in processes:

        parent_id = process["ppid"]

        if parent_id not in process_tree:
            process_tree[parent_id] = []

        process_tree[parent_id].append(process)

    return process_map, process_tree


def display_process_tree(processes):

    process_map, process_tree = build_process_tree(processes)

    print("\n===== PARENT-CHILD PROCESS RELATIONSHIPS =====")

    count = 0

    for parent_id, children in process_tree.items():

        parent = process_map.get(parent_id)

        if parent is None:
            continue

        print(
            f"\nPARENT: {parent['name']} "
            f"(PID: {parent_id})"
        )

        for child in children:

            print(
                f"    └── CHILD: {child['name']} "
                f"(PID: {child['pid']})"
            )

            count += 1

    print("\nTotal Parent-Child Relationships:", count)


if __name__ == "__main__":

    from process_monitor import collect_processes

    processes = collect_processes()

    display_process_tree(processes)
