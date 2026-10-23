from pirelywebamilen.flood import FloodRebound, LOOPBACK_REBOUND


def test_allows_normal_traffic():
    f = FloodRebound(per_second=100)
    for _ in range(99):
        assert f.check("1.1.1.1") is None


def test_rebounds_at_threshold():
    f = FloodRebound(per_second=5)
    out = [f.check("2.2.2.2", now=100.0 + i * 0.01) for i in range(6)]
    assert out[:4] == [None] * 4
    assert out[4] == LOOPBACK_REBOUND
    assert out[5] == LOOPBACK_REBOUND


def test_switches_to_decoy_under_heavier_flood():
    f = FloodRebound(per_second=5, decoy_to="http://decoy.example/")
    f.check("3.3.3.3", now=10.0)
    targets = [f.check("3.3.3.3", now=10.0 + i * 0.001) for i in range(20)]
    assert "http://decoy.example/" in targets


def test_window_slides_back_to_normal():
    f = FloodRebound(per_second=3)
    for i in range(3):
        f.check("4.4.4.4", now=20.0 + i * 0.01)
    assert f.check("4.4.4.4", now=21.5) is None


def test_ips_are_independent():
    f = FloodRebound(per_second=2)
    f.check("5.5.5.5", now=1.0)
    f.check("5.5.5.5", now=1.0)
    assert f.check("5.5.5.5", now=1.0) == LOOPBACK_REBOUND
    assert f.check("6.6.6.6", now=1.0) is None


def test_bad_configuration_rejected():
    import pytest

    with pytest.raises(ValueError):
        FloodRebound(per_second=0)
