import unittest

from tools.majiro.pipeline import file_key, review_label


class FileKeyTests(unittest.TestCase):
    def test_existing_mappings(self):
        self.assertEqual(file_key("01ルリエロルート05"), "ero05")
        self.assertEqual(file_key("01ルリ明るいルート05"), "route05")
        self.assertEqual(file_key("00プロローグ05"), "prologue05")
        self.assertEqual(file_key("start"), "start")

    def test_death_route_mapping(self):
        self.assertEqual(file_key("01ルリ死別ルート01"), "shibetsu01")
        self.assertEqual(file_key("01ルリ死別ルート10"), "shibetsu10")
        self.assertEqual(review_label("01ルリ死別ルート02"), "shibetsu02")


if __name__ == "__main__":
    unittest.main()