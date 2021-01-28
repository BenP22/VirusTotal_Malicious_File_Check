import unittest

from main import create_table


class TestMethods(unittest.TestCase):

    def test_create_table_success(self):
        header = '## hello\n'
        data = {'a': 1, 'b': 2, 'c': 5}
        expected_string = '## hello\n| _a_ | _b_ | _c_ | \n| ------ | ------ | ------ |\n| 1 | 2 | 5 | \n\n'
        with open('dummy_data', 'w+') as md_file:
            create_table(md_file, data, header=header)
        with open(md_file.name, 'r') as file:
            return_value = file.read()

        self.assertEqual(expected_string, return_value)

    def test_create_table_fail(self):
        header = '## hello\n'
        data = {'a': 1, 'b': 2}
        expected_string = '## hello\n| _a_ | _b_ | \n| ------ | ------ | ------ |\n| 1 | 2 | \n\n'
        with open('dummy_data', 'w+') as md_file:
            create_table(md_file, data, header=header)
        with open(md_file.name, 'r') as file:
            return_value = file.read()

        self.assertNotEqual(expected_string, return_value)
