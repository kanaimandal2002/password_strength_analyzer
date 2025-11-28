from analyzer.analyzer import entropy_bits
def test_entropy_increases_with_length():
    e1 = entropy_bits("abc")
    e2 = entropy_bits("abcdef")
    assert e2 > e1
