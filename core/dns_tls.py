import ipaddress
import os
import socket
import ssl
import tempfile
import time


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def resolve_a(host, timeout=5):
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []
    finally:
        socket.setdefaulttimeout(old)


def dns_records(host, timeout=5):
    result = {}
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            try:
                answer = resolver.resolve(host, rtype, raise_on_no_answer=False)
                if answer.rrset:
                    result[rtype] = [d.to_text().strip('"') for d in answer]
            except Exception:
                continue
    except ImportError:
        a = resolve_a(host, timeout=timeout)
        if a:
            result["A"] = a
    try:
        canonical = socket.gethostbyname_ex(host)
        if canonical[1]:
            result.setdefault("CNAME_CHAIN", canonical[1])
    except Exception:
        pass
    return result


def _flatten_name(entries):
    parts = []
    for rdn in entries or []:
        for attribute in rdn:
            try:
                if len(attribute) == 2:
                    parts.append(str(attribute[1]))
            except TypeError:
                parts.append(str(attribute))
    return ", ".join(parts)


def tls_cert_info(host, port=443, timeout=8):
    info = {"host": host, "port": port}
    try:
        try:
            pem = ssl.get_server_certificate((host, port), timeout=timeout)
        except TypeError:
            pem = ssl.get_server_certificate((host, port))
    except Exception as exc:
        info["error"] = f"TLS handshake failed: {exc}"
        return info
    info["pem"] = pem
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            tmp = fh.name
        decoded = ssl._ssl._test_decode_cert(tmp)
        info["subject"] = _flatten_name(decoded.get("subject"))
        info["issuer"] = _flatten_name(decoded.get("issuer"))
        info["not_before"] = decoded.get("notBefore")
        info["not_after"] = decoded.get("notAfter")
        info["sans"] = [v for k, v in decoded.get("subjectAltName", []) if k.lower() == "dns"]
    except Exception as exc:
        info["parse_error"] = str(exc)
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    if info.get("not_after"):
        try:
            expiry = ssl.cert_time_to_seconds(info["not_after"])
            info["days_left"] = int((expiry - time.time()) // 86400)
        except Exception:
            pass
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                info["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["verify_error"] = getattr(exc, "verify_message", None) or str(exc)
    except Exception as exc:
        info.setdefault("verified", None)
        info.setdefault("verify_error", str(exc))
    return info


def port_open(host, port, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False
