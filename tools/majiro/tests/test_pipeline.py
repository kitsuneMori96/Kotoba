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

    def test_bright_route_supplement_mapping(self):
        self.assertEqual(file_key("01ルリ明るいルート00_02"), "akarui0002")
        self.assertEqual(file_key("01ルリ明るいルート00_03"), "akarui0003")
        self.assertEqual(review_label("01ルリ明るいルート00_02"), "明亮路线00_02")
        self.assertNotEqual(file_key("01ルリ明るいルート00_02"), file_key("01ルリ明るいルート02"))
        self.assertNotEqual(review_label("01ルリ明るいルート00_02"), review_label("01ルリ明るいルート02"))

    def test_heroine_route_mapping(self):
        self.assertEqual(file_key("02佑咲ルート00"), "yusaki00")
        self.assertEqual(file_key("02佑咲ルート09"), "yusaki09")
        self.assertEqual(review_label("02佑咲ルート00"), "佑咲路线00")
        self.assertEqual(file_key("03いいちこルート01"), "iichiko01")
        self.assertEqual(review_label("03いいちこルート09"), "依知子路线09")
        self.assertNotEqual(file_key("02佑咲ルート00"), file_key("03いいちこルート01"))


if __name__ == "__main__":
    unittest.main()