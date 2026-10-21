import base64, json, unittest
from jwtguard.analyzer import JWTError, analyze_token
def seg(obj):
    return base64.urlsafe_b64encode(json.dumps(obj,separators=(",",":")).encode()).decode().rstrip("=")
def token(header=None,claims=None,signature="sig"):
    return seg(header or {"alg":"HS256","typ":"JWT"})+"."+seg(claims or {"exp":2000000000,"iss":"issuer","aud":"api"})+"."+signature
class Tests(unittest.TestCase):
    def test_decode_and_no_signature_claim(self):
        result=analyze_token(token(),now=100)
        self.assertEqual(result["header"]["alg"],"HS256")
        self.assertFalse(result["signature_verified"])
    def test_none_alg_and_empty_signature(self):
        codes={f["code"] for f in analyze_token(token({"alg":"none"},{"exp":2000000000},""),now=100)["findings"]}
        self.assertIn("JWT-002",codes); self.assertIn("JWT-013",codes)
    def test_expired(self):
        self.assertIn("JWT-009",{f["code"] for f in analyze_token(token(claims={"exp":1}),now=100)["findings"]})
    def test_missing_claims(self):
        codes={f["code"] for f in analyze_token(token(claims={}),now=100)["findings"]}
        self.assertIn("JWT-008",codes); self.assertIn("JWT-011",codes)
    def test_sensitive_header(self):
        result=analyze_token(token({"alg":"RS256","jku":"https://example.invalid/key"},{"exp":2000000000}),now=100)
        self.assertIn("JWT-004",{f["code"] for f in result["findings"]})
    def test_bad_time_type(self):
        self.assertIn("JWT-007",{f["code"] for f in analyze_token(token(claims={"exp":"later"}),now=100)["findings"]})
    def test_invalid_part_count(self):
        with self.assertRaises(JWTError): analyze_token("one.two")
    def test_invalid_json(self):
        with self.assertRaises(JWTError): analyze_token("not-base64.eyJ4IjoxfQ.sig")
    def test_empty_token(self):
        with self.assertRaises(JWTError): analyze_token("")
    def test_future_nbf(self):
        self.assertIn("JWT-012",{f["code"] for f in analyze_token(token(claims={"exp":2000,"nbf":200}),now=100)["findings"]})
if __name__=="__main__": unittest.main()
