import json
import math

import numpy as np
import pytest

from src.preprocessing.feature_extractor import (
    ALL_FEATURE_NAMES,
    ARTIFACT_RISK_FEATURES,
    DEFAULT_FEATURE_NAMES,
    FeatureExtractor,
    FeatureScaler,
    compute_features,
    shannon_entropy,
)
from src.preprocessing.url_normalizer import normalize_url


def feats(url: str, mode: str = "full_url") -> dict[str, float]:
    return compute_features(normalize_url(url, mode))  # type: ignore[arg-type]


class TestEntropy:
    def test_known_values(self):
        assert shannon_entropy("") == 0.0
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("ab") == pytest.approx(1.0)
        assert shannon_entropy("abcd") == pytest.approx(2.0)

    def test_random_looking_beats_repetitive(self):
        assert shannon_entropy("x7Qp2zK9mB4w") > shannon_entropy("aaaaaaaaaaab")


class TestFeatureDefinitions:
    def test_names_are_unique_and_defaults_exclude_artifact_features(self):
        assert len(set(ALL_FEATURE_NAMES)) == len(ALL_FEATURE_NAMES)
        assert not (set(DEFAULT_FEATURE_NAMES) & ARTIFACT_RISK_FEATURES)
        assert set(feats("https://example.com")) == set(ALL_FEATURE_NAMES)

    def test_known_example_exact_values(self):
        f = feats("https://sub.example.com/a/b?x=1&y=2")
        # model_string = "sub.example.com/a/b?x=1&y=2" (27 chars)
        assert f["url_length"] == 27
        assert f["host_length"] == 15
        assert f["path_length"] == 4
        assert f["query_length"] == 7
        assert f["registered_domain_length"] == 11
        assert f["num_host_labels"] == 3
        assert f["num_subdomain_labels"] == 1
        assert f["num_dots"] == 2
        assert f["num_digits"] == 2
        assert f["digit_ratio"] == pytest.approx(2 / 27)
        assert f["num_special_chars"] == 8
        assert f["special_char_ratio"] == pytest.approx(8 / 27)
        assert f["host_hyphens"] == 0
        assert f["host_digit_ratio"] == 0
        assert f["longest_host_label"] == 7
        assert f["num_underscores"] == 0
        assert f["num_percent_encoded"] == 0
        assert f["num_query_params"] == 2
        assert f["path_depth"] == 2
        assert f["longest_path_segment"] == 1
        assert f["is_ip_host"] == 0 and f["has_punycode"] == 0
        assert f["has_userinfo"] == 0 and f["has_nondefault_port"] == 0
        assert f["is_https"] == 1 and f["scheme_inferred"] == 0

    def test_subdomains_and_multi_part_suffix(self):
        f = feats("https://a.b.c.example.co.uk/")
        assert f["num_subdomain_labels"] == 3
        assert f["registered_domain_length"] == 13

    def test_ip_host(self):
        f = feats("http://192.168.0.1:8080/x")
        assert f["is_ip_host"] == 1
        assert f["host_length"] == 11
        assert f["num_host_labels"] == 0 and f["num_subdomain_labels"] == 0
        assert f["longest_host_label"] == 0 and f["registered_domain_length"] == 0
        assert f["has_nondefault_port"] == 1

    def test_ipv6_host_does_not_crash(self):
        f = feats("http://[2001:db8::1]/x")
        assert f["is_ip_host"] == 1 and f["num_host_labels"] == 0

    def test_punycode_and_hyphens(self):
        f = feats("https://münchen.de/")
        assert f["has_punycode"] == 1
        assert f["host_hyphens"] == 3  # xn--mnchen-3ya

    def test_userinfo_and_ports(self):
        assert feats("http://user:pw@example.com/")["has_userinfo"] == 1
        assert feats("https://example.com:443/")["has_nondefault_port"] == 0
        assert feats("https://example.com:8443/")["has_nondefault_port"] == 1

    def test_scheme_features(self):
        assert feats("https://example.com")["is_https"] == 1
        assert feats("http://example.com")["is_https"] == 0
        f = feats("example.com")
        assert f["scheme_inferred"] == 1 and f["is_https"] == 0

    def test_special_characters(self):
        assert feats("https://example.com/a%20b?q=%7e")["num_percent_encoded"] == 1
        assert feats("http://a_b.example.com/x_y")["num_underscores"] == 2
        assert feats("https://my-site-name.example.com")["host_hyphens"] == 2
        assert feats("http://a1b2.example.com")["host_digit_ratio"] == pytest.approx(0.125)

    def test_path_features(self):
        f = feats("http://example.com/")
        assert f["path_length"] == 1 and f["path_depth"] == 0 and f["longest_path_segment"] == 0
        f = feats("http://example.com/a//bb/ccc/")
        assert f["path_depth"] == 3 and f["longest_path_segment"] == 3

    def test_empty_query_pieces_are_not_counted(self):
        assert feats("http://example.com/?a=1&&b=2&")["num_query_params"] == 2

    def test_domain_mode(self):
        f = feats("Example.COM", "domain")
        assert f["url_length"] == f["host_length"] == 11
        assert f["path_length"] == 0 and f["query_length"] == 0 and f["path_depth"] == 0
        assert f["entropy_path_query"] == 0
        assert f["is_https"] == 0 and f["scheme_inferred"] == 0

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com",
            "http://192.168.0.1/",
            "https://münchen.de/café?q=ü",
            "http://user:pw@a-b.example.org:8080/p/q?x=%7e&y=2",
            "https://example.com/" + "a1-_%20" * 700,
            "x.co",
        ],
    )
    def test_values_are_finite_and_within_bounds(self, url):
        f = feats(url)
        for name, value in f.items():
            assert math.isfinite(value) and value >= 0, name
        for ratio in ("digit_ratio", "special_char_ratio", "host_digit_ratio"):
            assert 0.0 <= f[ratio] <= 1.0
        assert f["entropy_url"] <= math.log2(max(f["url_length"], 1)) + 1e-9


class TestFeatureExtractor:
    def test_default_vector(self):
        n = normalize_url("https://sub.example.com/a")
        vec = FeatureExtractor().extract(n)
        assert vec.dtype == np.float32 and vec.shape == (len(DEFAULT_FEATURE_NAMES),)
        assert "is_https" not in FeatureExtractor().feature_names

    def test_custom_names_keep_requested_order(self):
        n = normalize_url("https://sub.example.com/a")
        vec = FeatureExtractor(["host_length", "url_length"]).extract(n)
        f = compute_features(n)
        assert list(vec) == [f["host_length"], f["url_length"]]

    def test_artifact_features_can_be_enabled_explicitly(self):
        ex = FeatureExtractor(ALL_FEATURE_NAMES)
        assert "is_https" in ex.feature_names

    @pytest.mark.parametrize("names", [[], ["url_length", "url_length"], ["not_a_feature"]])
    def test_invalid_names(self, names):
        with pytest.raises(ValueError):
            FeatureExtractor(names)

    def test_batch_matches_single_and_handles_empty(self):
        ex = FeatureExtractor()
        items = [normalize_url(u) for u in ("https://a.com", "http://10.0.0.1/x", "b.org/y?z=1")]
        batch = ex.extract_batch(items)
        assert batch.shape == (3, len(ex.feature_names))
        for row, item in enumerate(items):
            assert (batch[row] == ex.extract(item)).all()
        assert ex.extract_batch([]).shape == (0, len(ex.feature_names))

    def test_rejects_non_normalized_input(self):
        with pytest.raises(TypeError):
            FeatureExtractor().extract("example.com")  # type: ignore[arg-type]

    def test_deterministic(self):
        n = normalize_url("https://sub.example.com/a?b=1")
        ex = FeatureExtractor()
        assert (ex.extract(n) == ex.extract(n)).all()


class TestFeatureScaler:
    def test_two_point_example_by_hand(self):
        # col0 is log1p-scaled (url_length), col1 is not (digit_ratio).
        raw = np.array([[1.0, 0.2], [3.0, 0.4]])
        scaler = FeatureScaler.fit(["url_length", "digit_ratio"], raw)
        assert np.allclose(scaler.transform(raw), [[-1, -1], [1, 1]], atol=1e-5)

    def test_standardised_columns_have_zero_mean_unit_std(self):
        rng = np.random.default_rng(0)
        raw = np.column_stack([rng.integers(5, 300, 500), rng.random(500), rng.integers(0, 2, 500)])
        names = ["url_length", "digit_ratio", "is_ip_host"]
        out = FeatureScaler.fit(names, raw).transform(raw)
        assert np.allclose(out.mean(axis=0), 0, atol=1e-4)
        assert np.allclose(out.std(axis=0), 1, atol=1e-4)

    def test_constant_column_maps_to_zero(self):
        raw = np.array([[0.0, 0.1], [0.0, 0.3]])
        out = FeatureScaler.fit(["is_ip_host", "digit_ratio"], raw).transform(raw)
        assert np.isfinite(out).all() and (out[:, 0] == 0).all()

    def test_one_dimensional_input_returns_one_dimensional_output(self):
        raw = np.array([[1.0, 0.2], [3.0, 0.4]])
        scaler = FeatureScaler.fit(["url_length", "digit_ratio"], raw)
        assert scaler.transform(raw[0]).shape == (2,)

    def test_bad_inputs(self):
        names = ["url_length", "digit_ratio"]
        good = np.array([[1.0, 0.2], [3.0, 0.4]])
        with pytest.raises(ValueError):
            FeatureScaler.fit(names, np.zeros((0, 2)))
        with pytest.raises(ValueError):
            FeatureScaler.fit(names, np.zeros((2, 3)))
        with pytest.raises(ValueError):
            FeatureScaler.fit(["url_length"], np.array([[-1.0]]))
        with pytest.raises(ValueError):
            FeatureScaler.fit(names, np.array([[np.nan, 0.1], [1.0, 0.2]]))
        scaler = FeatureScaler.fit(names, good)
        with pytest.raises(ValueError):
            scaler.transform(np.zeros((2, 3)))
        with pytest.raises(ValueError):
            scaler.transform(np.array([[np.inf, 0.1]]))

    def test_round_trip(self, tmp_path):
        raw = np.array([[1.0, 0.2], [3.0, 0.4], [10.0, 0.9]])
        scaler = FeatureScaler.fit(["url_length", "digit_ratio"], raw)
        path = tmp_path / "models" / "feature_config.json"
        scaler.save(path)
        loaded = FeatureScaler.load(path)
        assert loaded.fingerprint() == scaler.fingerprint()
        assert np.array_equal(loaded.transform(raw), scaler.transform(raw))

    def test_fingerprint_changes_with_statistics(self):
        a = FeatureScaler(["url_length"], [1.0], [1.0])
        b = FeatureScaler(["url_length"], [2.0], [1.0])
        assert a.fingerprint() != b.fingerprint() and len(a.fingerprint()) == 64

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda c: c.update(format_version=99),
            lambda c: c.update(type="other"),
            lambda c: c.update(mean=c["mean"][:-1]),
            lambda c: c["std"].__setitem__(0, 0.0),
            lambda c: c["feature_names"].__setitem__(0, "nope"),
            lambda c: c.pop("std"),
        ],
    )
    def test_tampered_files_are_rejected(self, tmp_path, mutate):
        scaler = FeatureScaler(["url_length", "digit_ratio"], [1.0, 0.5], [2.0, 0.1])
        config = scaler.to_config()
        mutate(config)
        path = tmp_path / "f.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        with pytest.raises(ValueError):
            FeatureScaler.load(path)

    @pytest.mark.parametrize("content", ["{not json", "[]", "42"])
    def test_garbage_files_are_rejected(self, tmp_path, content):
        path = tmp_path / "f.json"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError):
            FeatureScaler.load(path)


def test_extractor_and_scaler_work_together():
    urls = ["https://example.com", "http://192.168.0.1:8080/a/b?x=1", "https://münchen.de/café",
            "http://a-b.c.example.co.uk/p/q/r?x=1&y=2&z=3", "b.org", "https://x.com/" + "a" * 300]
    ex = FeatureExtractor()
    raw = ex.extract_batch([normalize_url(u) for u in urls])
    scaler = FeatureScaler.fit(ex.feature_names, raw)
    out = scaler.transform(raw)
    assert out.shape == raw.shape and np.isfinite(out).all()