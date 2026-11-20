from store import Store


def test_case_round_trip(tmp_path):
    store = Store(tmp_path / "cases.db")
    case = store.create_case(
        "Loopback scan investigation",
        "high",
        "Saarthak",
        ["alert-1"],
    )

    loaded = store.get_case(case["id"])
    assert loaded["title"] == "Loopback scan investigation"
    assert loaded["status"] == "new"
    assert loaded["alert_ids"] == ["alert-1"]

    note = store.add_case_note(case["id"], "Analyst", "Source IP reviewed.")
    assert store.get_case(case["id"])["notes"][0]["id"] == note["id"]


def test_heartbeat_becomes_online_only_after_real_event(tmp_path):
    store = Store(tmp_path / "heartbeat.db")
    initial = store.get_host_status("Saarthak")
    assert initial["status"] == "unknown"
    assert initial["last_seen"] is None

    timestamp = store.heartbeat("Saarthak", "test")
    assert timestamp
    current = store.get_host_status("Saarthak")
    assert current["status"] == "online"
