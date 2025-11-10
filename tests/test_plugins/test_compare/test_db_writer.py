"""Unit tests for database writer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import pytest

from capmaster.plugins.compare.db_writer import DatabaseWriter


@pytest.mark.integration
class TestDatabaseWriter:
    """Test DatabaseWriter class."""

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

    def test_insert_flow_hash_batch_empty_list(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test insert_flow_hash_batch with empty list."""
        with patch('psycopg2.connect', return_value=mock_connection):
            with DatabaseWriter("host=localhost", 1) as db:
                # Should not raise error with empty list
                db.insert_flow_hash_batch([])
                
                # executemany should not be called
                mock_cursor.executemany.assert_not_called()

    def test_insert_flow_hash_batch_single_record(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test insert_flow_hash_batch with single record."""
        with patch('psycopg2.connect', return_value=mock_connection):
            with DatabaseWriter("host=localhost", 1) as db:
                records = [{
                    'pcap_id': 1,
                    'flow_hash': 12345678901234567890,
                    'first_time': 1000000000000,
                    'last_time': 2000000000000,
                    'tcp_flags_different_cnt': 5,
                    'tcp_flags_different_type': 'SYN -> ACK',
                    'tcp_flags_different_text': 'Frame 1→2; Frame 3→4',
                    'seq_num_different_cnt': 3,
                    'seq_num_different_text': 'Frame 1→2: 1000→2000',
                }]
                
                db.insert_flow_hash_batch(records)
                
                # Verify executemany was called once
                assert mock_cursor.executemany.call_count == 1
                
                # Verify SQL contains correct table name
                sql = mock_cursor.executemany.call_args[0][0]
                assert 'kase_1_tcp_stream_extra' in sql
                
                # Verify data was passed correctly
                data = mock_cursor.executemany.call_args[0][1]
                assert len(data) == 1
                assert data[0][0] == 1  # pcap_id
                assert data[0][1] == 12345678901234567890  # flow_hash
                assert data[0][2] == 1000000000000  # first_time
                assert data[0][3] == 2000000000000  # last_time
                assert data[0][4] == 5  # tcp_flags_different_cnt
                assert data[0][5] == 'SYN -> ACK'  # tcp_flags_different_type
                assert data[0][6] == 'Frame 1→2; Frame 3→4'  # tcp_flags_different_text
                assert data[0][7] == 3  # seq_num_different_cnt
                assert data[0][8] == 'Frame 1→2: 1000→2000'  # seq_num_different_text

    def test_insert_flow_hash_batch_multiple_records(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test insert_flow_hash_batch with multiple records."""
        with patch('psycopg2.connect', return_value=mock_connection):
            with DatabaseWriter("host=localhost", 1) as db:
                records = [
                    {
                        'pcap_id': 1,
                        'flow_hash': 11111111111111111111,
                        'first_time': 1000000000000,
                        'last_time': 2000000000000,
                        'tcp_flags_different_cnt': 5,
                        'tcp_flags_different_type': 'SYN -> ACK',
                        'tcp_flags_different_text': 'Frame 1→2',
                        'seq_num_different_cnt': 3,
                        'seq_num_different_text': 'Frame 1→2: 1000→2000',
                    },
                    {
                        'pcap_id': 1,
                        'flow_hash': 22222222222222222222,
                        'first_time': 3000000000000,
                        'last_time': 4000000000000,
                        'tcp_flags_different_cnt': 2,
                        'tcp_flags_different_type': 'ACK -> FIN',
                        'tcp_flags_different_text': 'Frame 10→11',
                        'seq_num_different_cnt': 1,
                        'seq_num_different_text': 'Frame 10→11: 5000→6000',
                    },
                    {
                        'pcap_id': 1,
                        'flow_hash': 33333333333333333333,
                        'first_time': 5000000000000,
                        'last_time': 6000000000000,
                        'tcp_flags_different_cnt': 0,
                        'tcp_flags_different_type': None,
                        'tcp_flags_different_text': '',
                        'seq_num_different_cnt': 0,
                        'seq_num_different_text': '',
                    },
                ]
                
                db.insert_flow_hash_batch(records)
                
                # Verify executemany was called once
                assert mock_cursor.executemany.call_count == 1
                
                # Verify data contains all 3 records
                data = mock_cursor.executemany.call_args[0][1]
                assert len(data) == 3
                
                # Verify first record
                assert data[0][0] == 1
                assert data[0][1] == 11111111111111111111
                
                # Verify second record
                assert data[1][0] == 1
                assert data[1][1] == 22222222222222222222
                
                # Verify third record
                assert data[2][0] == 1
                assert data[2][1] == 33333333333333333333

    def test_insert_flow_hash_batch_handles_none_text_fields(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test insert_flow_hash_batch converts None to empty string for text fields."""
        with patch('psycopg2.connect', return_value=mock_connection):
            with DatabaseWriter("host=localhost", 1) as db:
                records = [{
                    'pcap_id': 1,
                    'flow_hash': 12345678901234567890,
                    'first_time': 1000000000000,
                    'last_time': 2000000000000,
                    'tcp_flags_different_cnt': 0,
                    'tcp_flags_different_type': None,
                    'tcp_flags_different_text': None,  # Should be converted to ''
                    'seq_num_different_cnt': 0,
                    'seq_num_different_text': None,  # Should be converted to ''
                }]
                
                db.insert_flow_hash_batch(records)
                
                # Verify None was converted to empty string
                data = mock_cursor.executemany.call_args[0][1]
                assert data[0][6] == ''  # tcp_flags_different_text
                assert data[0][8] == ''  # seq_num_different_text

    def test_insert_flow_hash_batch_handles_missing_optional_fields(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test insert_flow_hash_batch handles missing optional fields."""
        with patch('psycopg2.connect', return_value=mock_connection):
            with DatabaseWriter("host=localhost", 1) as db:
                records = [{
                    'pcap_id': 1,
                    'flow_hash': 12345678901234567890,
                    # Missing optional fields
                }]
                
                db.insert_flow_hash_batch(records)
                
                # Verify defaults were used
                data = mock_cursor.executemany.call_args[0][1]
                assert data[0][2] is None  # first_time
                assert data[0][3] is None  # last_time
                assert data[0][4] == 0  # tcp_flags_different_cnt
                assert data[0][5] is None  # tcp_flags_different_type
                assert data[0][6] == ''  # tcp_flags_different_text
                assert data[0][7] == 0  # seq_num_different_cnt
                assert data[0][8] == ''  # seq_num_different_text

    def test_insert_flow_hash_batch_not_connected(self):
        """Test insert_flow_hash_batch raises error when not connected."""
        db = DatabaseWriter.__new__(DatabaseWriter)
        db._cursor = None
        db._conn = None
        
        with pytest.raises(RuntimeError, match="Database not connected"):
            db.insert_flow_hash_batch([{'pcap_id': 1, 'flow_hash': 123}])

    def test_insert_flow_hash_single_vs_batch_equivalence(self, mock_connection: MagicMock, mock_cursor: MagicMock):
        """Test that batch insert produces same result as individual inserts."""
        with patch('psycopg2.connect', return_value=mock_connection):
            # Test individual inserts
            with DatabaseWriter("host=localhost", 1) as db:
                db.insert_flow_hash(
                    pcap_id=1,
                    flow_hash=11111111111111111111,
                    first_time=1000000000000,
                    last_time=2000000000000,
                    tcp_flags_different_cnt=5,
                    tcp_flags_different_type='SYN -> ACK',
                    tcp_flags_different_text=['Frame 1→2'],
                    seq_num_different_cnt=3,
                    seq_num_different_text=['Frame 1→2: 1000→2000'],
                )
                db.insert_flow_hash(
                    pcap_id=1,
                    flow_hash=22222222222222222222,
                    first_time=3000000000000,
                    last_time=4000000000000,
                    tcp_flags_different_cnt=2,
                    tcp_flags_different_type='ACK -> FIN',
                    tcp_flags_different_text=['Frame 10→11'],
                    seq_num_different_cnt=1,
                    seq_num_different_text=['Frame 10→11: 5000→6000'],
                )
            
            # Get individual insert calls
            individual_calls = [call[0][1] for call in mock_cursor.execute.call_args_list]
            
            # Reset mock
            mock_cursor.reset_mock()
            
            # Test batch insert
            with DatabaseWriter("host=localhost", 1) as db:
                records = [
                    {
                        'pcap_id': 1,
                        'flow_hash': 11111111111111111111,
                        'first_time': 1000000000000,
                        'last_time': 2000000000000,
                        'tcp_flags_different_cnt': 5,
                        'tcp_flags_different_type': 'SYN -> ACK',
                        'tcp_flags_different_text': ['Frame 1→2'],
                        'seq_num_different_cnt': 3,
                        'seq_num_different_text': ['Frame 1→2: 1000→2000'],
                    },
                    {
                        'pcap_id': 1,
                        'flow_hash': 22222222222222222222,
                        'first_time': 3000000000000,
                        'last_time': 4000000000000,
                        'tcp_flags_different_cnt': 2,
                        'tcp_flags_different_type': 'ACK -> FIN',
                        'tcp_flags_different_text': ['Frame 10→11'],
                        'seq_num_different_cnt': 1,
                        'seq_num_different_text': ['Frame 10→11: 5000→6000'],
                    },
                ]
                db.insert_flow_hash_batch(records)
            
            # Get batch insert data
            batch_data = mock_cursor.executemany.call_args[0][1]
            
            # Verify batch data matches individual inserts
            assert len(batch_data) == len(individual_calls)
            for i, individual_data in enumerate(individual_calls):
                assert batch_data[i] == individual_data

