import logging
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from capmaster.utils.context import ExecutionContext
from capmaster.utils.errors import StrictModeError
from capmaster.plugins.match.server_detector import ServerDetector

@pytest.fixture
def reset_context():
    """Reset execution context before and after tests."""
    ExecutionContext.set_strict(False)
    ExecutionContext.set_quiet(False)
    yield
    ExecutionContext.set_strict(False)
    ExecutionContext.set_quiet(False)

def test_strict_mode_error(reset_context, tmp_path):
    """Test that warnings raise StrictModeError in strict mode."""
    ExecutionContext.set_strict(True)
    
    # Create a malformed service list
    service_list = tmp_path / "services.txt"
    service_list.write_text("invalid_line\n", encoding="utf-8")
    
    # The constructor calls _load_service_list, so it should raise immediately
    with pytest.raises(StrictModeError, match="Strict mode violation"):
        ServerDetector(service_list_path=service_list)

def test_normal_mode_warning(reset_context, tmp_path, caplog):
    """Test that warnings are just logged in normal mode."""
    ExecutionContext.set_strict(False)
    
    service_list = tmp_path / "services.txt"
    service_list.write_text("invalid_line\n", encoding="utf-8")
    
    with caplog.at_level(logging.WARNING):
        detector = ServerDetector(service_list_path=service_list)
    
    assert "Invalid format in service list" in caplog.text

def test_allow_no_input_flag():
    """Test that InputManager handles allow_no_input correctly."""
    from capmaster.core.input_manager import InputManager
    import click
    
    # Test with allow_no_input=True
    with pytest.raises(click.exceptions.Exit) as exc:
        InputManager.validate_file_count([], min_files=1, allow_no_input=True)
    assert exc.value.exit_code == 0
    
    # Test with allow_no_input=False
    with pytest.raises(click.BadParameter):
        InputManager.validate_file_count([], min_files=1, allow_no_input=False)
