import logging
import os
import typing
from collections.abc import Sequence
from dataclasses import dataclass

import cbor2
import mmh3
import semver

JsonPrimitive: typing.TypeAlias = str | bool | float | int
JsonLogicArg: typing.TypeAlias = JsonPrimitive | Sequence[JsonPrimitive]

logger = logging.getLogger("openfeature.contrib")


@dataclass
class Fraction:
    variant: str
    weight: int = 1


def fractional(data: dict, *args: typing.Any) -> str | None:
    if not args:
        logger.error("No arguments provided to fractional operator.")
        return None

    bucket_by = None
    if not isinstance(args[0], (list, tuple)):
        bucket_by = args[0]
        args = args[1:]
    else:
        seed = data.get("$flagd", {}).get("flagKey", "")
        targeting_key = data.get("targetingKey")
        if not targeting_key:
            logger.error("No targetingKey provided for fractional shorthand syntax.")
            return None
        bucket_by = seed + targeting_key

    if bucket_by is None:
        logger.error("No hashKey value resolved")
        return None

    # New hashing logic using CBOR
    bucket_by = normalize_numbers(bucket_by)
    deterministic_cbor_bytes = cbor2.dumps(bucket_by, canonical=True)
    hash_value = mmh3.hash(deterministic_cbor_bytes, signed=False)

    # Invoke verification helper
    if not verify_test(data, f"{hash_value:08x}", deterministic_cbor_bytes):
        raise ValueError(f"Verification failed for test {data.get('id')}")

    bucket = (hash_value / 4294967295.0) * 100

    logger.debug(f"Bucket value for '{bucket_by}': {bucket}")

    total_weight = 0
    fractions = []
    try:
        for arg in args:
            fraction = _parse_fraction(arg)
            if fraction:
                fractions.append(fraction)
                total_weight += fraction.weight

    except ValueError:
        logger.debug(f"Invalid {args} configuration")
        return None

    range_end: float = 0
    for fraction in fractions:
        range_end += fraction.weight * 100 / total_weight
        if bucket < range_end:
            return fraction.variant
    return None


def _parse_fraction(arg: JsonLogicArg) -> Fraction:
    if not isinstance(arg, (tuple, list)) or not arg or len(arg) > 2:
        raise ValueError(
            "Fractional variant weights must be (str, int) tuple or [str] list"
        )

    if not isinstance(arg[0], str):
        raise ValueError(
            "Fractional variant identifier (first element) isn't of type 'str'"
        )

    if len(arg) >= 2 and not isinstance(arg[1], int):
        raise ValueError(
            "Fractional variant weight value (second element) isn't of type 'int'"
        )

    fraction = Fraction(variant=arg[0])
    if len(arg) >= 2:
        fraction.weight = arg[1]

    return fraction


def starts_with(data: dict, *args: JsonLogicArg) -> bool | None:
    def f(s1: str, s2: str) -> bool:
        return s1.startswith(s2)

    return string_comp(f, data, *args)


def ends_with(data: dict, *args: JsonLogicArg) -> bool | None:
    def f(s1: str, s2: str) -> bool:
        return s1.endswith(s2)

    return string_comp(f, data, *args)


def string_comp(
    comparator: typing.Callable[[str, str], bool], data: dict, *args: JsonLogicArg
) -> bool | None:
    if not args:
        logger.error("No arguments provided to string_comp operator.")
        return None
    if len(args) != 2:
        logger.error("Exactly 2 args expected for string_comp operator.")
        return None
    arg1, arg2 = args
    if not isinstance(arg1, str):
        logger.debug(f"incorrect argument for first argument, expected string: {arg1}")
        return False
    if not isinstance(arg2, str):
        logger.debug(f"incorrect argument for second argument, expected string: {arg2}")
        return False

    return comparator(arg1, arg2)


def sem_ver(data: dict, *args: JsonLogicArg) -> bool | None:  # noqa: C901
    if not args:
        logger.error("No arguments provided to sem_ver operator.")
        return None
    if len(args) != 3:
        logger.error("Exactly 3 args expected for sem_ver operator.")
        return None

    arg1, op, arg2 = args

    try:
        v1 = parse_version(arg1)
        v2 = parse_version(arg2)
    except ValueError as e:
        logger.exception(e)
        return None

    if op == "=":
        return v1 == v2
    elif op == "!=":
        return v1 != v2
    elif op == "<":
        return v1 < v2
    elif op == "<=":
        return v1 <= v2
    elif op == ">":
        return v1 > v2
    elif op == ">=":
        return v1 >= v2
    elif op == "^":
        return v1.major == v2.major
    elif op == "~":
        return v1.major == v2.major and v1.minor == v2.minor
    else:
        logger.error(f"Op not supported by sem_ver: {op}")
        return None


def parse_version(arg: typing.Any) -> semver.Version:
    version = str(arg)
    if version.startswith(("v", "V")):
        version = version[1:]

    return semver.Version.parse(version)


def normalize_numbers(data: typing.Any) -> typing.Any:
    """
    Recursively convert floats that have no fractional part into integers,
    but only if they fit within the 64-bit signed integer range.
    This ensures consistency for small integers (like 0.0 -> 0)
    while avoiding converting massive floats into bignums, which
    cause encoding differences.
    """
    if isinstance(data, dict):
        return {k: normalize_numbers(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [normalize_numbers(v) for v in data]
    elif isinstance(data, float) and data.is_integer():
        # Check if it fits in 64-bit signed integer range
        if -(2**63) <= data <= 2**63 - 1:
            return int(data)
    return data


def verify_test(data: dict, calculated_hash: str, calculated_cbor: bytes) -> bool:
    """
    Helper function to verify the CBOR encoding and hash for a test case.
    Expects 'id' and 'path' to be present in the data (evaluation context)
    to perform verification against files.
    """
    test_id = data.get("id")
    test_path = data.get("path")

    if test_id is None or test_path is None:
        return True

    hash_file = os.path.join(test_path, f"{test_id}.hash")
    cbor_file = os.path.join(test_path, f"{test_id}.cbor")

    if not os.path.exists(hash_file) or not os.path.exists(cbor_file):
        return True

    try:
        with open(hash_file, "r") as f:
            expected_hash = f.read().strip().strip('"')

        with open(cbor_file, "rb") as f:
            expected_cbor = f.read()

        if calculated_hash != expected_hash:
            print(
                f"VERIFY_TEST FAIL: test {test_id}, hash mismatch: expected {expected_hash}, got {calculated_hash}"
            )
            return False

        if calculated_cbor != expected_cbor:
            print(f"VERIFY_TEST FAIL: test {test_id}, cbor mismatch")
            return False

        return True
    except Exception as e:
        print(f"VERIFY_TEST ERROR: test {test_id}, {e}")
        return False
