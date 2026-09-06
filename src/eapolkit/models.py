from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .attributes import encode_value


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PasswordInput(InputModel):
    password: str = Field(min_length=1, max_length=4096)


class RadiusAttribute(InputModel):
    id: int = Field(ge=1, le=255, strict=True)
    type: Literal["string", "integer", "hex", "ipaddr"]
    key: str | None = Field(default=None, min_length=1, max_length=128)
    sensitivity: Literal["public", "private"] | None = None
    value: str | None = Field(default=None, max_length=506, repr=False)

    @model_validator(mode="after")
    def validate_attribute(self):
        if "value" in self.model_fields_set:
            encode_value({"id": self.id, "type": self.type, "value": self.value})
        if "sensitivity" in self.model_fields_set and self.sensitivity is None:
            raise ValueError("A supplied sensitivity must be public or private")
        return self


def printable(value: str) -> str:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Control characters are not allowed")
    return value


def dns_or_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Expected a DNS name or IP address") from None
    if len(ascii_value) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9.])?", ascii_value):
        raise ValueError("Expected a DNS name or IP address")
    for label in ascii_value.rstrip(".").split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError("Expected a DNS name or IP address")
    return ascii_value.lower()


class TargetInput(InputModel):
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=1812, ge=1, le=65535)
    timeout_seconds: int = Field(default=30, ge=5, le=120)
    nas_identifier: str = Field(default="eapol-test-kit", max_length=253)
    nas_ip_address: str | None = None
    calling_station_id: str = Field(default="02:00:00:00:00:01", max_length=253)
    extra_attributes: list[RadiusAttribute] = Field(default_factory=list, max_length=32)
    secret: str | None = Field(default=None, min_length=1, max_length=4096, repr=False)

    _name = field_validator("name", "nas_identifier", "calling_station_id")(printable)
    _host = field_validator("host")(dns_or_ip)

    @field_validator("secret")
    @classmethod
    def secret_bytes(cls, value):
        if value is not None and ("\x00" in value or len(value.encode("utf-8")) > 4096):
            raise ValueError("RADIUS secret must be at most 4096 UTF-8 bytes and must not contain NUL")
        return value

    @field_validator("nas_ip_address")
    @classmethod
    def nas_address(cls, value):
        if not value:
            return None
        try:
            return str(ipaddress.IPv4Address(value))
        except ValueError:
            raise ValueError("NAS-IP-Address must be an IPv4 address") from None


Method = Literal["eap-tls", "peap-mschapv2", "ttls-pap", "ttls-mschapv2"]
Outcome = Literal["accept", "reject", "certificate_error"]


class ProfileInput(InputModel):
    name: str = Field(min_length=1, max_length=120)
    method: Method
    identity: str = Field(default="", max_length=1024)
    anonymous_identity: str | None = Field(default=None, max_length=1024)
    ca_certificate_id: str | None = Field(default=None, max_length=128)
    client_identity_id: str | None = Field(default=None, max_length=128)
    server_name: str = Field(default="", max_length=253)
    tls_min_version: Literal["1.2", "1.3"] = "1.2"
    tls_max_version: Literal["auto", "1.2", "1.3"] = "auto"
    fragment_size: int = Field(default=1398, ge=100, le=65535)
    expected_outcome: Outcome = "accept"
    allow_expired_client_certificate: bool = False
    password: str | None = Field(default=None, min_length=1, max_length=4096, repr=False)

    _name = field_validator("name")(printable)

    @field_validator("server_name")
    @classmethod
    def server_dns(cls, value):
        if not value:
            return value
        return dns_or_ip(value)

    @model_validator(mode="after")
    def tls_range(self):
        if self.tls_max_version != "auto" and self.tls_max_version < self.tls_min_version:
            raise ValueError("Maximum TLS version must not be lower than minimum TLS version")
        return self


KeyType = Literal["rsa2048", "rsa3072", "ec-p256"]


class CAInput(InputModel):
    name: str = Field(min_length=1, max_length=120)
    common_name: str = Field(min_length=1, max_length=64)
    days: int = Field(default=3650, ge=1, le=36500)
    key_type: KeyType = "rsa3072"
    _labels = field_validator("name", "common_name")(printable)


class CSRInput(InputModel):
    name: str = Field(min_length=1, max_length=120)
    common_name: str = Field(min_length=1, max_length=64)
    key_type: KeyType = "rsa3072"
    san_dns: list[str] = Field(default_factory=list, max_length=32)
    san_email: list[str] = Field(default_factory=list, max_length=32)
    san_uri: list[str] = Field(default_factory=list, max_length=32)
    _labels = field_validator("name", "common_name")(printable)


class ClientInput(CSRInput):
    issuer_id: str = Field(min_length=1, max_length=128)
    days: int = Field(default=365, ge=1, le=36500)


class ExportInput(InputModel):
    passphrase: str = Field(min_length=8, max_length=4096, repr=False)


class DuplicateInput(InputModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    expected_outcome: Outcome | None = None


class RunInput(InputModel):
    target_id: str = Field(min_length=1, max_length=128)
    profile_id: str = Field(min_length=1, max_length=128)
    expected_outcome: Outcome | None = None


def presets() -> list[dict]:
    labels = {"eap-tls": "EAP-TLS", "peap-mschapv2": "PEAP / MSCHAPv2", "ttls-pap": "EAP-TTLS / PAP", "ttls-mschapv2": "EAP-TTLS / MSCHAPv2"}
    return [dict(ProfileInput(name=label, method=method).model_dump(exclude={"password"}), has_password=False) for method, label in labels.items()]
