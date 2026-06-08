from cascade.panel.auth import hash_password, verify_password


def test_hash_then_verify_ok():
    h = hash_password("s3cret")
    assert h.startswith("pbkdf2_sha256$")
    assert verify_password("s3cret", h) is True


def test_verify_wrong_password():
    h = hash_password("s3cret")
    assert verify_password("nope", h) is False


def test_hash_salts_differ():
    assert hash_password("x") != hash_password("x")


def test_verify_garbage_hash():
    assert verify_password("x", "") is False
    assert verify_password("x", "not$a$valid$hash$extra") is False
