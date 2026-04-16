"""Intentionally-unsafe fixture for GovClaw experiment E02.

Do not import this module. It exists so DefenseClaw's scanner and CodeGuard
have a known-bad target to produce a CRITICAL verdict against.
"""
import hashlib
import pickle
import subprocess

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def run_cmd(user_input: str) -> None:
    subprocess.call(f"echo {user_input}", shell=True)


def load_blob(b: bytes):
    return pickle.loads(b)


def hash_pw(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()
