import unittest
from server_client import NTLMv2Client, NTLMv2Server


class TestServerMethods(unittest.TestCase):
    """Test full client-server interaction."""

    def test_ok(self):
        client = NTLMv2Client()
        client.authenticate('user1', '12345', 'example.com')
        assert client.send('Hello World') == 'Hello World'

    def test_missing_session(self):
        with self.assertRaises(KeyError):
            server = NTLMv2Server()
            client = NTLMv2Client(server)
            client.authenticate('user1', '12345', 'example.com')
            server.sessions.clear()
            client.send('Hello World') == 'Hello World'

    def test_missing_user(self):
        with self.assertRaises(KeyError):
            client = NTLMv2Client()
            client.authenticate('user3', '12345', 'example.com')


if __name__ == '__main__':
    unittest.main()
