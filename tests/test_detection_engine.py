import unittest
from modules.detection_engine import detect_suspicious_relationships


class TestDetectionEngine(unittest.TestCase):

    def test_suspicious_relationship_detected(self):

        processes = [
            {
                "pid": 100,
                "ppid": 50,
                "name": "powershell.exe"
            },
            {
                "pid": 50,
                "ppid": 1,
                "name": "winword.exe"
            }
        ]

        alerts = detect_suspicious_relationships(processes)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["parent"], "winword.exe")
        self.assertEqual(alerts[0]["child"], "powershell.exe")

    def test_normal_relationship_not_detected(self):

        processes = [
            {
                "pid": 100,
                "ppid": 50,
                "name": "notepad.exe"
            },
            {
                "pid": 50,
                "ppid": 1,
                "name": "explorer.exe"
            }
        ]

        alerts = detect_suspicious_relationships(processes)

        self.assertEqual(len(alerts), 0)

    def test_missing_parent_not_detected(self):

        processes = [
            {
                "pid": 100,
                "ppid": 999,
                "name": "powershell.exe"
            }
        ]

        alerts = detect_suspicious_relationships(processes)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()