from calc import add, double


def test_double():
    assert double(21) == 42


def test_add():
    assert add(2, 3) == 5
