import json

import numpy as np
import pytest

from src.preprocessing.tokenizer import (
    DEFAULT_CHARSET,
    NUM_RESERVED,
    PAD_ID,
    TRUNC_ID,
    UNK_ID,
    URLTokenizer,
)
from src.preprocessing.url_normalizer import normalize_url


def cid(ch: str) -> int:
    return DEFAULT_CHARSET.index(ch) + NUM_RESERVED


class TestVocabulary:
    def test_sizes_and_reserved_ids(self):
        tok = URLTokenizer()
        assert len(DEFAULT_CHARSET) == 94
        assert tok.vocab_size == 97
        assert len({PAD_ID, UNK_ID, TRUNC_ID}) == 3
        assert max(PAD_ID, UNK_ID, TRUNC_ID) < NUM_RESERVED
        assert cid("!") == 3 and cid("~") == 96

    def test_case_is_preserved(self):
        tok = URLTokenizer()
        assert tok.encode("A").ids[0] != tok.encode("a").ids[0]


class TestEncoding:
    def test_short_input_is_right_padded(self):
        enc = URLTokenizer(max_length=16, tail_length=4).encode("ab/")
        assert enc.ids.shape == (16,) and enc.ids.dtype == np.int64
        assert list(enc.ids[:3]) == [cid("a"), cid("b"), cid("/")]
        assert (enc.ids[3:] == PAD_ID).all()
        assert enc.length == 3 and enc.truncated is False and enc.original_length == 3

    def test_empty_string(self):
        enc = URLTokenizer(max_length=16, tail_length=4).encode("")
        assert enc.length == 0 and (enc.ids == PAD_ID).all() and enc.truncated is False

    def test_unknown_characters_map_to_unk(self):
        enc = URLTokenizer(max_length=16, tail_length=4).encode("a é b")
        assert list(enc.ids[:5]) == [cid("a"), UNK_ID, UNK_ID, UNK_ID, cid("b")]

    def test_non_str_input_rejected(self):
        tok = URLTokenizer()
        for bad in (None, 123, b"abc"):
            with pytest.raises(TypeError):
                tok.encode(bad)  # type: ignore[arg-type]

    def test_returned_arrays_are_independent(self):
        tok = URLTokenizer(max_length=16, tail_length=4)
        first = tok.encode("abc")
        first.ids[0] = 99
        assert tok.encode("abc").ids[0] == cid("a")

    def test_decode_round_trip(self):
        tok = URLTokenizer(max_length=32, tail_length=8)
        text = "example.com/a?b=1"
        assert tok.decode(tok.encode(text).ids) == text


class TestTruncation:
    def make(self):
        return URLTokenizer(max_length=16, tail_length=4)

    def test_boundary(self):
        tok = self.make()
        exact = tok.encode("a" * 16)
        assert exact.truncated is False and exact.length == 16
        over = tok.encode("a" * 17)
        assert over.truncated is True and over.length == 16

    def test_keeps_head_and_tail_with_marker(self):
        tok = self.make()
        enc = tok.encode("abcdefghijklmnopqrstuvwxyz")
        assert tok.head_length == 11
        assert enc.truncated is True
        assert enc.original_length == 26
        assert enc.length == 16
        assert enc.ids[11] == TRUNC_ID
        assert (enc.ids != PAD_ID).all()
        assert tok.decode(enc.ids) == "abcdefghijk<TRUNC>wxyz"

    def test_zero_tail_length(self):
        tok = URLTokenizer(max_length=16, tail_length=0)
        enc = tok.encode("abcdefghijklmnopqrstuvwxyz")
        assert tok.decode(enc.ids) == "abcdefghijklmno<TRUNC>"
        assert enc.length == 16

    def test_very_long_input(self):
        tok = URLTokenizer()
        enc = tok.encode("h" + "x" * 5000 + "z")
        assert enc.truncated and enc.length == tok.max_length
        assert enc.ids[0] == cid("h") and enc.ids[-1] == cid("z")


class TestBatch:
    def test_matches_single_encoding(self):
        tok = URLTokenizer(max_length=16, tail_length=4)
        texts = ["a", "bcd" * 10, "", "exact-sixteen-chr"]
        batch = tok.encode_batch(texts)
        assert batch.ids.shape == (4, 16)
        for row, text in enumerate(texts):
            single = tok.encode(text)
            assert (batch.ids[row] == single.ids).all()
            assert batch.lengths[row] == single.length
            assert batch.truncated[row] == single.truncated

    def test_empty_batch(self):
        batch = URLTokenizer(max_length=16, tail_length=4).encode_batch([])
        assert batch.ids.shape == (0, 16) and batch.lengths.shape == (0,)

    def test_single_string_is_rejected(self):
        with pytest.raises(TypeError):
            URLTokenizer().encode_batch("example.com")  # type: ignore[arg-type]


class TestConfigValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            dict(max_length=4, tail_length=0),
            dict(max_length=16, tail_length=-1),
            dict(max_length=16, tail_length=15),
            dict(charset=""),
            dict(charset="aab"),
            dict(charset="a b"),
        ],
    )
    def test_bad_values(self, kwargs):
        with pytest.raises(ValueError):
            URLTokenizer(**kwargs)

    @pytest.mark.parametrize(
        "kwargs",
        [dict(max_length="16"), dict(tail_length=1.5), dict(max_length=True), dict(charset=None)],
    )
    def test_bad_types(self, kwargs):
        with pytest.raises(TypeError):
            URLTokenizer(**kwargs)


class TestSerialization:
    def test_round_trip(self, tmp_path):
        tok = URLTokenizer(max_length=32, tail_length=8)
        path = tmp_path / "models" / "tokenizer.json"  # parent dir does not exist yet
        tok.save(path)
        loaded = URLTokenizer.load(path)
        assert loaded.fingerprint() == tok.fingerprint()
        text = "example.com/" + "a" * 100
        assert (loaded.encode(text).ids == tok.encode(text).ids).all()
        path.read_text(encoding="ascii")  # file is pure ASCII

    def test_fingerprint_is_stable_and_sensitive(self):
        a = URLTokenizer(max_length=32, tail_length=8)
        assert a.fingerprint() == URLTokenizer(max_length=32, tail_length=8).fingerprint()
        assert len(a.fingerprint()) == 64
        assert a.fingerprint() != URLTokenizer(max_length=64, tail_length=8).fingerprint()
        assert a.fingerprint() != URLTokenizer(max_length=32, tail_length=8, charset="abc").fingerprint()

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda c: c.update(format_version=99),
            lambda c: c.update(type="something_else"),
            lambda c: c.update(unk_id=5),
            lambda c: c.pop("charset"),
        ],
    )
    def test_tampered_or_incompatible_files_are_rejected(self, tmp_path, mutate):
        tok = URLTokenizer(max_length=32, tail_length=8)
        config = tok.to_config()
        mutate(config)
        path = tmp_path / "t.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        with pytest.raises(ValueError):
            URLTokenizer.load(path)

    @pytest.mark.parametrize("content", ["{not json", "[]", '"text"'])
    def test_garbage_files_are_rejected(self, tmp_path, content):
        path = tmp_path / "t.json"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(ValueError):
            URLTokenizer.load(path)


@pytest.mark.parametrize(
    "url",
    [
        "https://Example.COM/Path?Q=1",
        "https://münchen.de/café?q=ü",
        "http://user:pw@evil.example:8080/p?x=%7e",
        "http://[2001:DB8::1]/x",
        "ftp://files.example.org/a b".replace(" ", "%20"),
    ],
)
def test_normalised_urls_never_produce_unk(url):
    """Contract between modules: the normalizer's output fits the vocabulary."""
    tok = URLTokenizer()
    enc = tok.encode(normalize_url(url).model_string)
    assert UNK_ID not in enc.ids[: enc.length]