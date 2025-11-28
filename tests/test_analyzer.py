from analyzer.analyzer import PasswordReport
def test_common_password_detected():
    rpt = PasswordReport("password", common_passwords_path=None)
    rpt.common = set(["password"])
    res = rpt.analyze()
    assert res['common_password_match'] is True
