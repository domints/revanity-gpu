from revanity_gpu.native_cuda import NativeCudaBridge


def test_native_bridge_graceful_unavailable():
    bridge = NativeCudaBridge()
    if bridge.available():
        # Environment may provide compiled native library.
        assert bridge.load_error == ""
    else:
        assert bridge.load_error != ""
        assert bridge.scan_prefix_suffix(b"\x00" * 64, "dead", "prefix") is None
