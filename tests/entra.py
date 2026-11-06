"""A local stand-in for Azure Entra ID: an RSA key, its JWKS and a token minter. No network."""
from __future__ import annotations

import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

TENANT = "11111111-2222-3333-4444-555555555555"  # EXAMPLE tenant id
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
AUDIENCE = "api://pharma-platform"
ROLE_MAP = {"CMC.Lead": "cmc_lead", "Quality.Assurance": "qa", "aaaaaaaa-0000-0000-0000-00000000b0d0": ["bd"]}


class FakeEntra:
    def __init__(self, kid: str = "test-key-1") -> None:
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
        self.jwks = {"keys": [jwk]}

    def token(self, *, oid: str = "0a1b2c3d-0000-4000-8000-000000000001", roles=("CMC.Lead",), groups=(),
              aud: str = AUDIENCE, iss: str = ISSUER, tid: str = TENANT, ttl: int = 3600,
              auth_time: float | None = None, name: str = "Casey Ng") -> str:
        now = int(time.time())
        claims = {"iss": iss, "aud": aud, "iat": now, "nbf": now, "exp": now + ttl, "oid": oid,
                  "sub": "pairwise-" + oid, "tid": tid, "name": name, "roles": list(roles),
                  "groups": list(groups), "auth_time": int(auth_time if auth_time is not None else now),
                  "jti": str(uuid.uuid4())}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": self.kid})
