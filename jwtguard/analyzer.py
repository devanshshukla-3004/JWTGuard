import base64
import json
import time

class JWTError(ValueError):
    pass

def _decode(segment):
    try:
        raw = base64.urlsafe_b64decode((segment + "=" * (-len(segment) % 4)).encode("ascii"))
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise JWTError("Invalid base64url JSON segment") from exc
    if not isinstance(value, dict):
        raise JWTError("JWT header and payload must be JSON objects")
    return value

def analyze_token(token, now=None):
    if not isinstance(token, str) or not token.strip():
        raise JWTError("Token must not be empty")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JWTError("Expected a three-part compact JWS; encrypted JWE is not supported")
    header, claims = _decode(parts[0]), _decode(parts[1])
    now = int(time.time()) if now is None else int(now)
    findings = []
    def add(code, severity, title, evidence, recommendation):
        findings.append({"code":code,"severity":severity,"title":title,"evidence":evidence,"recommendation":recommendation})
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        add("JWT-001","HIGH","Missing or invalid alg","alg is absent or not a string","Configure an explicit algorithm allow-list in the verifier")
    elif alg.lower() == "none":
        add("JWT-002","HIGH","Unsecured algorithm declared","Header declares alg=none","Reject unsecured tokens unless explicitly required by a narrowly defined design")
    elif alg.lower().startswith("hs"):
        add("JWT-003","INFO","Symmetric signing algorithm","Header declares "+alg,"Protect the shared secret and explicitly allow-list algorithms")
    for key in sorted({"jku","x5u","jwk","x5c"} & set(header)):
        severity = "HIGH" if key in {"jku","x5u"} else "MEDIUM"
        add("JWT-004",severity,"Review security-sensitive "+key,"Header contains "+key,"Never blindly trust token-supplied key material or remote key locations")
    if "kid" in header:
        if not isinstance(header["kid"],str) or not header["kid"].strip():
            add("JWT-005","MEDIUM","Suspicious kid value","kid is not a non-empty string","Validate key IDs and map them safely to trusted keys")
        else:
            add("JWT-006","INFO","Key identifier present","kid is untrusted until validated","Resolve key IDs only against trusted key sets")
    for key in ("exp","iat","nbf"):
        if key in claims and (isinstance(claims[key],bool) or not isinstance(claims[key],(int,float))):
            add("JWT-007","MEDIUM","Invalid "+key+" claim type",key+" should be a numeric date","Validate time claim types during token verification")
    exp=claims.get("exp")
    if "exp" not in claims:
        add("JWT-008","MEDIUM","Expiration claim absent","Payload has no exp claim","Require exp when expected by the application's token profile")
    elif isinstance(exp,(int,float)) and not isinstance(exp,bool):
        if exp <= now:
            add("JWT-009","HIGH","Token appears expired","exp="+str(exp),"Reject expired tokens during server-side verification")
        else:
            add("JWT-010","INFO","Expiration is in the future","exp="+str(exp),"Still verify signature, issuer, audience, and application claims")
    for key in ("iss","aud"):
        if key not in claims:
            add("JWT-011","LOW",key+" claim absent","Payload has no "+key,"Require and validate this claim if the application's profile requires it")
    nbf=claims.get("nbf")
    if isinstance(nbf,(int,float)) and not isinstance(nbf,bool) and nbf > now:
        add("JWT-012","MEDIUM","Token not yet active","nbf="+str(nbf),"Reject tokens before their not-before time")
    if not parts[2]:
        add("JWT-013","HIGH","Empty signature segment","Third token segment is empty","Require integrity protection and verify signatures with trusted keys")
    score=min(100,sum({"HIGH":30,"MEDIUM":15,"LOW":5,"INFO":0}[x["severity"]] for x in findings))
    return {"tool":"JWTGuard","version":"1.0.0","analysis_mode":"offline_structure_and_claims_only","signature_verified":False,"header":header,"claims":claims,"findings":findings,"finding_count":len(findings),"risk_score":score,"risk_label":"HIGH" if score>=60 else "MEDIUM" if score>=25 else "LOW","limitations":["Signatures are not verified; token authenticity is not established.","Decoded claims remain untrusted until cryptographically verified.","Findings are triage leads, not proof of exploitability."]}
