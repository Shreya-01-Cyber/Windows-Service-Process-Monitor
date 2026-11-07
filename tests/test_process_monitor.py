import unittest
from modules.process_monitor import collect_processes


class TestProcessMonitor(unittest.TestCase):

    def test_process_collection_returns_list(self):
        processes = collect_processes()

        self.assertIsInstance(processes, list)

    def test_process_entries_have_required_fields(self):
        processes = collect_processes()

        required_fields = [
            "pid",
            "ppid",
            "name",
            "path",
            "username"
        ]

        for process in processes:
            for field in required_fields:
                self.assertIn(field, process)

    def test_process_ids_are_integers(self):
        processes = collect_processes()

        for process in processes:
            self.assertIsInstance(process["pid"], int)


if __name__ == "__main__":
    unittest.main()