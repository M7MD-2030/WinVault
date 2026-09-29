from winvault.auditing import AuditItem, is_fully_enabled, parse_auditpol_csv

HEADER = "Machine Name,Policy Target,Subsystem,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting"


def test_parse_success():
    text = f"{HEADER}\nPC,System,,Process Creation,{{0CCE922B-69AE-11D9-BED3-505054503030}},Success,\n"
    assert parse_auditpol_csv(text) is True


def test_parse_success_and_failure():
    text = f"{HEADER}\nPC,System,,Process Creation,{{0CCE922B}},Success and Failure,\n"
    assert parse_auditpol_csv(text) is True


def test_parse_no_auditing():
    text = f"{HEADER}\nPC,System,,Process Creation,{{0CCE922B}},No Auditing,\n"
    assert parse_auditpol_csv(text) is False


def test_parse_unknown_locale_is_undetermined_not_wrong():
    text = f"{HEADER}\nPC,System,,Prozesserstellung,{{0CCE922B}},Erfolg,\n"
    assert parse_auditpol_csv(text) is None
    assert parse_auditpol_csv("") is None


def test_fully_enabled():
    assert is_fully_enabled([AuditItem("a", True, ""), AuditItem("b", True, "")])
    assert not is_fully_enabled([AuditItem("a", True, ""), AuditItem("b", None, "")])
