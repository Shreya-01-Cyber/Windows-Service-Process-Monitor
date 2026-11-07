import unittest
from unittest.mock import patch
from modules.service_monitor import collect_services


class TestServiceMonitor(unittest.TestCase):

    @patch("modules.service_monitor.subprocess.run")
    def test_service_collection_returns_list(self, mock_run):

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            '[{"Name":"Spooler",'
            '"DisplayName":"Print Spooler",'
            '"State":"Running",'
            '"StartMode":"Auto"}]'
        )

        services = collect_services()

        self.assertIsInstance(services, list)
        self.assertEqual(len(services), 1)

    @patch("modules.service_monitor.subprocess.run")
    def test_service_details_are_collected(self, mock_run):

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            '[{"Name":"Spooler",'
            '"DisplayName":"Print Spooler",'
            '"State":"Running",'
            '"StartMode":"Auto"}]'
        )

        services = collect_services()

        self.assertEqual(services[0]["Name"], "Spooler")
        self.assertEqual(services[0]["State"], "Running")
        self.assertEqual(services[0]["StartMode"], "Auto")


if __name__ == "__main__":
    unittest.main()