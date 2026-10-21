# JWTGuard

Offline defensive JWT structure and claims analyzer. It decodes three-part compact JWS tokens and flags review-worthy header and claim patterns.

IMPORTANT: This tool does not verify signatures or prove token authenticity. Decoding is not verification. Treat decoded values as untrusted. Use synthetic or authorized tokens only; do not commit production tokens.

## Features
- Inspect header and payload locally
- Flag alg=none, missing algorithm metadata, empty signature segments, sensitive key-reference headers, and unusual kid values
- Review exp, iat, nbf, iss, and aud claims
- Evidence, severity, remediation, heuristic risk score, JSON and CSV reports
- Python standard library only; no network calls

## Usage

    python jwtguard.py 'HEADER.PAYLOAD.SIGNATURE'
    python jwtguard.py --file samples/my-token.txt --output reports/analysis.json --csv reports/findings.csv
    python -m unittest discover -s tests -v

## Limitations
Does not verify signatures, issuer trust, audience matching, key strength, revocation, or server-side behavior. Encrypted JWE is not supported. Findings are triage leads, not proof of exploitability. iss/aud requirements depend on the application's token profile. The risk score is a prioritization heuristic, not a probability.

## References
- RFC 7519: https://www.rfc-editor.org/rfc/rfc7519.html
- RFC 8725: https://www.rfc-editor.org/rfc/rfc8725.html
- OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html

MIT License.
