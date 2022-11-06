"""Client-Server implementation, based on Microsoft NTLMv2 docs.

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
"""

import os
from utils import hmac_md5, md4, create_ntlm_response


class AuthException(Exception):
    pass


class NTLMv2Server:
    """NTLMv2 server implementation.

    Basic usage example:

    ```
        client = NTLMv2Client()
        client.authenticate('user1', '12345', 'example.com')
        assert client.send('Hello World') == 'Hello World'
    ```
    """

    DATABASE = {
        'user1': md4("12345"),
        'user2': md4("54321"),
    }

    def __init__(self):
        """Create session storage and server challeng variable."""

        self.server_challenge = os.urandom(8)
        self.sessions = {}

    def get_ntlm_auth_message(self):
        return self.server_challenge

    def authenticate(
        self, user: str,
        password: str,
        client_challenge: bytes,
        domain: str,
        lm_response_key: bytes,
        nt_response_key: bytes,
    ) -> bytes:
        """Creates Response object with session key.

        If auth failed, returns empty response.

        This method uses pseudo database without password hashing,
        original algorythm uses Microsoft Active Directory

        Args:
            user (str): username
            password (str): open password
            client_challenge (bytes): random byte sequence 8 bytes length
            domain (str): domain name

        Raises:
            KeyError: If user or password is invalid

        Returns:
            str: session_key for client
        """
        user_exists = user in self.DATABASE
        password_is_ok = self.DATABASE.get(user) == md4(password)

        if not user_exists or not password_is_ok:
            raise AuthException('401 Unauthorized')

        nt_challenge_response, lm_challenge_response, proof_str =\
            create_ntlm_response(
                user,
                password,
                domain,
                client_challenge,
                self.server_challenge,
            )

        # validate integrity
        if (lm_response_key != lm_challenge_response
                or nt_response_key != nt_challenge_response):
            raise AuthException('401 Unauthorized')

        session_key = hmac_md5(nt_challenge_response, proof_str)
        self.sessions[session_key] = user

        return session_key

    def authorize(self, session_key: bytes):
        """Validate key from session storage.

        Args:
            session_key (bytes): session key, created via authorization

        Raises:
            KeyError: If session key not found in storage
        """
        try:
            self.sessions[session_key]
        except KeyError as err:
            raise AuthException('401 Unauthorized') from err

    def request_echo(self, session_key: str, message: str) -> str:
        """Protected echo function, requires valid session key.

        Args:
            session_key (str): requested session key
            message (str): any text

        Returns:
            str: echo message
        """
        self.authorize(session_key)
        return message


class NTLMv2Client:
    """NTLMv2 simple client."""

    def __init__(self, server: NTLMv2Server=None):
        """Create NTLMv2 connection.

        Args:
            user (str): username.
            password (str): user password.
            domain (str): domain name.
            server (NTLMv2Server, optional):
                Set, if redefenition needed. Defaults to None.
        """
        self.client_challenge = os.urandom(8)
        self.conn = server or NTLMv2Server()
        self.session_key = b''

    def authenticate(self, user: str, password: str, domain: str) -> None:
        """Set session key for client, if pwd or user are invalid, raises Exc

        Args:
            user (str): username
            password (str): user password
            domain (str): domain name
        """
        server_challenge = self.conn.get_ntlm_auth_message()

        nt_key, lm_key, _ = create_ntlm_response(
            user, password,
            domain, self.client_challenge,
            server_challenge
        )

        session_key = self.conn.authenticate(
            user, password, self.client_challenge, domain, lm_key, nt_key)
        self.session_key = session_key

    def send(self, message: str) -> str:
        return self.conn.request_echo(self.session_key, message)
