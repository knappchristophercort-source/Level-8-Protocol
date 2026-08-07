import importlib
import unittest


class ScaffoldImportTests(unittest.TestCase):
    def test_package_modules_import(self) -> None:
        module_names = [
            "l8_reference.crypto",
            "l8_reference.identity",
            "l8_reference.attestation",
            "l8_reference.consensus",
            "l8_reference.ledger",
            "l8_reference.storage",
            "l8_reference.sentinel",
            "l8_reference.verifier",
            "l8_reference.observer",
        ]

        for module_name in module_names:
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                self.assertIsNotNone(module)


if __name__ == "__main__":
    unittest.main()
