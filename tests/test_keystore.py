"""Tests for l8_reference.keystore module."""
import pytest
import tempfile
from pathlib import Path
from l8_reference.keystore import (
    SoftwareKeyStore, KeyStoreFactory, KeyAlreadyExistsError, KeyNotFoundError
)
from l8_reference.crypto import L8Crypto


class TestSoftwareKeyStore:
    def test_generate_and_sign(self, tmp_path):
        store = SoftwareKeyStore(str(tmp_path))
        pub = store.generate_keypair("test-key-1", "ed25519")

        assert pub is not None
        assert len(pub) > 0
        assert store.exists("test-key-1")

    def test_sign_and_verify(self, tmp_path):
        store = SoftwareKeyStore(str(tmp_path))
        pub = store.generate_keypair("test-key-2", "ed25519")

        message = b"test message"
        sig = store.sign("test-key-2", message)

        pk = L8Crypto.deserialize_public_key(pub)
        assert L8Crypto.verify(pk, message, sig) is True

    def test_duplicate_key_rejected(self, tmp_path):
        store = SoftwareKeyStore(str(tmp_path))
        store.generate_keypair("dup-key", "ed25519")

        with pytest.raises(KeyAlreadyExistsError):
            store.generate_keypair("dup-key", "ed25519")

    def test_key_not_found(self, tmp_path):
        store = SoftwareKeyStore(str(tmp_path))

        with pytest.raises(KeyNotFoundError):
            store.sign("nonexistent", b"test")

        with pytest.raises(KeyNotFoundError):
            store.get_public_key("nonexistent")

    def test_list_and_delete(self, tmp_path):
        store = SoftwareKeyStore(str(tmp_path))
        store.generate_keypair("key-a", "ed25519")
        store.generate_keypair("key-b", "ed25519")

        keys = store.list_keys()
        assert sorted(keys) == ["key-a", "key-b"]

        assert store.delete_key("key-a") is True
        assert not store.exists("key-a")
        assert store.exists("key-b")

    def test_encrypted_keystore(self, tmp_path):
        store = SoftwareKeyStore(str(tmp_path), passphrase="super-secret-passphrase")
        pub = store.generate_keypair("enc-key", "ed25519")

        sig = store.sign("enc-key", b"encrypted signing test")
        pk = L8Crypto.deserialize_public_key(pub)
        assert L8Crypto.verify(pk, b"encrypted signing test", sig) is True

    def test_persistence(self, tmp_path):
        store1 = SoftwareKeyStore(str(tmp_path))
        pub1 = store1.generate_keypair("persist-key", "ed25519")

        store2 = SoftwareKeyStore(str(tmp_path))

        assert store2.exists("persist-key")
        assert store2.get_public_key("persist-key") == pub1

        sig = store2.sign("persist-key", b"persistent test")
        pk = L8Crypto.deserialize_public_key(pub1)
        assert L8Crypto.verify(pk, b"persistent test", sig) is True


class TestKeyStoreFactory:
    def test_software_backend(self, tmp_path):
        store = KeyStoreFactory.create("software", storage_dir=str(tmp_path))
        assert isinstance(store, SoftwareKeyStore)

        pub = store.generate_keypair("factory-key", "ed25519")
        assert pub is not None

    def test_unknown_backend(self):
        with pytest.raises(ValueError):
            KeyStoreFactory.create("unknown")
