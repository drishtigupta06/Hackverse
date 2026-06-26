import os
import pytest

DIVA_APK = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "diva", "diva.apk")


@pytest.fixture
def diva_apk_path():
    return os.path.abspath(DIVA_APK)
