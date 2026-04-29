#!/usr/bin/env python3
import argparse
import base64
import hashlib
import http.server
import ssl
import subprocess
import tempfile
import time
from pathlib import Path


EST_CACERTS_PATH = "/api/dmsmanager/.well-known/est/est-ra/cacerts"
EST_SIMPLEENROLL_PATH = "/api/dmsmanager/.well-known/est/est-ra/simpleenroll"
MLDSA44_OID = bytes.fromhex("608648016503040311")
CN_OID = bytes.fromhex("550403")
PKCS7_SIGNED_DATA_OID = bytes.fromhex("2A864886F70D010702")
PKCS7_DATA_OID = bytes.fromhex("2A864886F70D010701")
MLDSA44_SIGNATURE_LEN = 2420


def pem_to_pkcs7_b64(pem: str) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        certfile = td_path / "cert.pem"
        derfile = td_path / "certs.p7b.der"
        certfile.write_text(pem, encoding="ascii")

        subprocess.run(
            [
                "openssl",
                "crl2pkcs7",
                "-nocrl",
                "-certfile",
                str(certfile),
                "-outform",
                "DER",
                "-out",
                str(derfile),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        return base64.encodebytes(derfile.read_bytes()).replace(b"\n", b"\r\n")


def der_len(length: int) -> bytes:
    if length < 0:
        raise ValueError("negative DER length")
    if length < 0x80:
        return bytes([length])
    data = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(data)]) + data


def der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_len(len(content)) + content


def der_seq(*items: bytes) -> bytes:
    return der_tlv(0x30, b"".join(items))


def der_set(*items: bytes) -> bytes:
    return der_tlv(0x31, b"".join(items))


def der_ctx(tag_no: int, content: bytes) -> bytes:
    return der_tlv(0xA0 + tag_no, content)


def der_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative DER INTEGER not supported")
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if data[0] & 0x80:
        data = b"\x00" + data
    return der_tlv(0x02, data)


def der_oid(oid_content: bytes) -> bytes:
    return der_tlv(0x06, oid_content)


def der_utf8(value: str) -> bytes:
    return der_tlv(0x0C, value.encode("utf-8"))


def der_utctime(epoch: int) -> bytes:
    return der_tlv(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(epoch)).encode("ascii"))


def der_bit_string(payload: bytes) -> bytes:
    return der_tlv(0x03, b"\x00" + payload)


def mldsa44_algorithm_identifier() -> bytes:
    return der_seq(der_oid(MLDSA44_OID))


def parse_tlv(data: bytes, offset: int = 0) -> tuple[int, int, int, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated DER object")

    tag = data[offset]
    first_len = data[offset + 1]
    pos = offset + 2

    if first_len & 0x80:
        len_len = first_len & 0x7F
        if len_len == 0 or len_len > 4 or pos + len_len > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[pos:pos + len_len], "big")
        pos += len_len
    else:
        length = first_len

    end = pos + length
    if end > len(data):
        raise ValueError("DER object overruns input")

    return tag, pos, length, end


def der_children(seq_der: bytes, expected_tag: int = 0x30) -> list[bytes]:
    tag, content_start, content_len, content_end = parse_tlv(seq_der, 0)
    if tag != expected_tag or content_end != len(seq_der):
        raise ValueError("unexpected DER container")

    children = []
    pos = content_start
    while pos < content_start + content_len:
        _, _, _, end = parse_tlv(seq_der, pos)
        children.append(seq_der[pos:end])
        pos = end

    return children


def der_oid_content(oid_der: bytes) -> bytes:
    tag, content_start, content_len, content_end = parse_tlv(oid_der, 0)
    if tag != 0x06 or content_end != len(oid_der):
        raise ValueError("expected OID")
    return oid_der[content_start:content_start + content_len]


def read_common_name(name_der: bytes) -> str:
    try:
        for rdn_set in der_children(name_der, 0x30):
            for atv in der_children(rdn_set, 0x31):
                atv_children = der_children(atv, 0x30)
                if len(atv_children) != 2:
                    continue
                if der_oid_content(atv_children[0]) != CN_OID:
                    continue
                tag, start, length, _ = parse_tlv(atv_children[1], 0)
                if tag not in (0x0C, 0x13):
                    continue
                return atv_children[1][start:start + length].decode("utf-8", errors="replace")
    except ValueError:
        pass
    return "(unknown)"


def parse_mldsa44_csr(csr_der: bytes) -> tuple[bytes, bytes, str]:
    csr_children = der_children(csr_der, 0x30)
    if len(csr_children) != 3:
        raise ValueError("CSR must contain CRI, signatureAlgorithm, and signature")

    cri_der = csr_children[0]
    sig_alg_children = der_children(csr_children[1], 0x30)
    if not sig_alg_children or der_oid_content(sig_alg_children[0]) != MLDSA44_OID:
        raise ValueError("CSR signatureAlgorithm is not ML-DSA-44")

    cri_children = der_children(cri_der, 0x30)
    if len(cri_children) < 3:
        raise ValueError("CSR CertificationRequestInfo is incomplete")

    subject_der = cri_children[1]
    spki_der = cri_children[2]
    spki_children = der_children(spki_der, 0x30)
    if len(spki_children) != 2:
        raise ValueError("CSR SubjectPublicKeyInfo is malformed")

    spki_alg_children = der_children(spki_children[0], 0x30)
    if not spki_alg_children or der_oid_content(spki_alg_children[0]) != MLDSA44_OID:
        raise ValueError("CSR public key algorithm is not ML-DSA-44")

    return subject_der, spki_der, read_common_name(subject_der)


def build_mldsa44_certificate(csr_der: bytes, serial: int) -> tuple[bytes, str]:
    subject_der, spki_der, common_name = parse_mldsa44_csr(csr_der)
    now = int(time.time())
    one_year = 365 * 24 * 60 * 60
    issuer = der_seq(der_set(der_seq(der_oid(CN_OID), der_utf8("Adhoc ML-DSA RA"))))
    alg_id = mldsa44_algorithm_identifier()

    tbs = der_seq(
        der_ctx(0, der_int(2)),
        der_int(serial),
        alg_id,
        issuer,
        der_seq(der_utctime(now - 60), der_utctime(now + one_year)),
        subject_der,
        spki_der,
    )

    # OpenSSL 3.0 cannot produce ML-DSA signatures. This gives the client a
    # standards-shaped ML-DSA-44 certificate for EST transport/parser testing;
    # replace this with a real RA ML-DSA signer when one is available.
    signature = hashlib.shake_256(b"adhoc-mldsa44-x509-signature-v1" + tbs + csr_der).digest(
        MLDSA44_SIGNATURE_LEN
    )
    return der_seq(tbs, alg_id, der_bit_string(signature)), common_name


def cert_der_to_pkcs7_b64(cert_der: bytes) -> bytes:
    signed_data = der_seq(
        der_int(1),
        der_set(),
        der_seq(der_oid(PKCS7_DATA_OID)),
        der_ctx(0, cert_der),
        der_set(),
    )
    content_info = der_seq(der_oid(PKCS7_SIGNED_DATA_OID), der_ctx(0, signed_data))
    return base64.encodebytes(content_info).replace(b"\n", b"\r\n")


def compact_base64(data: bytes) -> bytes:
    return bytes(ch for ch in data if ch not in b" \t\r\n")


class AdhocEstRa(http.server.BaseHTTPRequestHandler):
    server_version = "AdhocESTRA/0.1"

    def do_GET(self) -> None:
        if self.path != EST_CACERTS_PATH:
            self.send_error(404)
            return

        print("GET cacerts")
        self.send_est_pkcs7(self.server.cacerts_body)

    def do_POST(self) -> None:
        if self.path != EST_SIMPLEENROLL_PATH:
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        csr_der = base64.b64decode(compact_base64(body), validate=True)

        print(f"POST simpleenroll: body={len(body)} bytes csr_der={len(csr_der)} bytes")
        try:
            serial = self.server.next_serial()
            cert_der, common_name = build_mldsa44_certificate(csr_der, serial)
            print(
                "Issued structural ML-DSA-44 certificate: "
                f"serial={serial} subject CN={common_name} der={len(cert_der)} bytes"
            )
        except Exception as exc:
            self.send_error(400, f"invalid ML-DSA-44 CSR: {exc}")
            return

        self.send_est_pkcs7(cert_der_to_pkcs7_b64(cert_der))

    def send_est_pkcs7(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
        self.send_header("Content-Transfer-Encoding", "base64")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.client_address[0]} - {fmt % args}")


class EstHttpServer(http.server.ThreadingHTTPServer):
    def __init__(self, server_address, handler_class, cacerts_body: bytes):
        super().__init__(server_address, handler_class)
        self.cacerts_body = cacerts_body
        self._serial = 1

    def next_serial(self) -> int:
        serial = self._serial
        self._serial += 1
        return serial


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal ad-hoc EST RA for STM32 testing")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default=str(Path(__file__).with_name("server.cert.pem")))
    parser.add_argument("--key", default=str(Path(__file__).with_name("server.key.pem")))
    args = parser.parse_args()

    ca_pem = Path(args.cert).read_text(encoding="ascii")

    server = EstHttpServer(
        (args.host, args.port),
        AdhocEstRa,
        cacerts_body=pem_to_pkcs7_b64(ca_pem),
    )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"Ad-hoc EST RA listening on https://{args.host}:{args.port}")
    print(f"  cacerts:      {EST_CACERTS_PATH}")
    print(f"  simpleenroll: {EST_SIMPLEENROLL_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
