"""Unit tests for MatchDatabaseWriter."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import pytest

from capmaster.plugins.match.db_writer import MatchDatabaseWriter


@pytest.mark.integration
class TestMatchDatabaseWriter:
    """Test MatchDatabaseWriter class."""

    @pytest.fixture
    def mock_connection(self) -> MagicMock:
        """Create a mock database connection."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        return mock_conn

    @pytest.fixture
    def mock_cursor(self, mock_connection: MagicMock) -> MagicMock:
        """Get the mock cursor from the connection."""
        return mock_connection.cursor.return_value

    def test_clear_table_data_when_table_exists(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test clear_table_data when table exists."""
        # Mock table existence check to return True
        mock_cursor.fetchone.return_value = (True,)
        
        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                db.clear_table_data()
                
                # Verify table existence was checked
                assert mock_cursor.execute.call_count >= 1
                
                # Verify TRUNCATE was called
                truncate_calls = [
                    call for call in mock_cursor.execute.call_args_list
                    if 'TRUNCATE' in str(call)
                ]
                assert len(truncate_calls) > 0, "TRUNCATE command should be executed"
                
                # Verify commit was called
                assert mock_connection.commit.called

    def test_clear_table_data_when_table_not_exists(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test clear_table_data when table does not exist."""
        # Mock table existence check to return False
        mock_cursor.fetchone.return_value = (False,)
        
        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                db.clear_table_data()
                
                # Verify table existence was checked
                assert mock_cursor.execute.call_count >= 1
                
                # Verify TRUNCATE was NOT called (only existence check)
                truncate_calls = [
                    call for call in mock_cursor.execute.call_args_list
                    if 'TRUNCATE' in str(call)
                ]
                assert len(truncate_calls) == 0, "TRUNCATE should not be executed when table doesn't exist"

    def test_ensure_table_exists_creates_table(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test ensure_table_exists creates table when it doesn't exist."""
        # Mock table existence check to return False
        mock_cursor.fetchone.return_value = (False,)
        
        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                db.ensure_table_exists()
                
                # Verify CREATE TABLE was called
                create_calls = [
                    call for call in mock_cursor.execute.call_args_list
                    if 'CREATE TABLE' in str(call)
                ]
                assert len(create_calls) > 0, "CREATE TABLE should be executed"
                
                # Verify CREATE SEQUENCE was called
                sequence_calls = [
                    call for call in mock_cursor.execute.call_args_list
                    if 'CREATE SEQUENCE' in str(call)
                ]
                assert len(sequence_calls) > 0, "CREATE SEQUENCE should be executed"

    def test_ensure_table_exists_skips_when_exists(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test ensure_table_exists skips creation when table exists."""
        # Mock table existence check to return True
        mock_cursor.fetchone.return_value = (True,)
        
        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                db.ensure_table_exists()
                
                # Verify CREATE TABLE was NOT called
                create_calls = [
                    call for call in mock_cursor.execute.call_args_list
                    if 'CREATE TABLE' in str(call)
                ]
                assert len(create_calls) == 0, "CREATE TABLE should not be executed when table exists"

    def test_table_name_construction(self):
        """Test that table name is constructed correctly from kase_id."""
        with patch('psycopg2.connect'):
            db = MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137)
            assert db.table_name == "kase_137_topological_graph"
            assert db.full_table_name == "public.kase_137_topological_graph"
            
            db2 = MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 999)
            assert db2.table_name == "kase_999_topological_graph"
            assert db2.full_table_name == "public.kase_999_topological_graph"

    def test_insert_node_basic(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test basic node insertion."""
        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                db.insert_node(
                    pcap_id=0,
                    group_id=1,
                    ip="192.168.1.1",
                    port=80,
                    proto=6,
                    node_type=2,
                    is_capture=False,
                    net_area=[],
                    stream_cnt=10,
                    pktlen=5000,
                    display_name="Test Node",
                )
                
                # Verify INSERT was called
                insert_calls = [
                    call for call in mock_cursor.execute.call_args_list
                    if 'INSERT INTO' in str(call)
                ]
                assert len(insert_calls) > 0, "INSERT should be executed"

    def test_context_manager_closes_connection(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test that context manager properly closes connection."""
        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                pass
            
            # Verify cursor and connection were closed
            assert mock_cursor.close.called, "Cursor should be closed"
            assert mock_connection.close.called, "Connection should be closed"

