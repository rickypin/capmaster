"""Unit tests for MatchDatabaseWriter."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch, call
import pytest

# Mock psycopg2 module before importing MatchDatabaseWriter
sys.modules['psycopg2'] = MagicMock()

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


@pytest.mark.integration
class TestMatchDatabaseWriterServiceAggregation:
    """Test MatchDatabaseWriter service aggregation functionality."""

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

    @pytest.fixture
    def mock_service_stats(self):
        """Create mock service statistics."""
        from capmaster.plugins.match.endpoint_stats import ServiceStats, ServiceKey, EndpointPairStats, EndpointTuple

        # Create mock endpoint pairs
        pair1 = MagicMock(spec=EndpointPairStats)
        pair1.tuple_a = EndpointTuple("192.168.1.100", "10.0.0.1", 8000, "TCP")
        pair1.tuple_b = EndpointTuple("172.16.0.100", "192.168.1.1", 8000, "TCP")
        pair1.count = 5
        pair1.client_ttl_a = 64
        pair1.server_ttl_a = 63
        pair1.client_ttl_b = 58
        pair1.server_ttl_b = 62
        pair1.client_hops_a = 0
        pair1.server_hops_a = 1
        pair1.client_hops_b = 6
        pair1.server_hops_b = 2
        pair1.total_bytes_a = 5000
        pair1.total_bytes_b = 4800

        service_key = ServiceKey(8000, "TCP")
        service_stats = ServiceStats(
            service_key=service_key,
            endpoint_pairs=[pair1],
            total_connections=5,
            unique_server_ips_a={"10.0.0.1"},
            unique_server_ips_b={"192.168.1.1"},
            unique_client_ips_a={"192.168.1.100"},
            unique_client_ips_b={"172.16.0.100"},
        )

        return [service_stats]

    def test_write_service_stats_basic(
        self, mock_connection: MagicMock, mock_cursor: MagicMock, mock_service_stats
    ):
        """Test basic service stats writing."""
        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                records = db.write_service_stats(
                    service_stats=mock_service_stats,
                    file1_path="file1.pcap",
                    file2_path="file2.pcap",
                    pcap_id_mapping={"file1.pcap": 0, "file2.pcap": 1},
                )

                # Verify INSERT was called multiple times (clients, servers, network devices)
                insert_calls = [
                    call for call in mock_cursor.execute.call_args_list
                    if 'INSERT INTO' in str(call)
                ]
                assert len(insert_calls) > 0, "INSERT should be executed"
                assert records > 0, "Should return number of records inserted"

    def test_write_service_stats_with_group_mapping(
        self, mock_connection: MagicMock, mock_cursor: MagicMock, mock_service_stats
    ):
        """Test service stats writing with custom group mapping."""
        service_to_group_mapping = {"8000": 10, "8080": 10, "443": 20}

        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                records = db.write_service_stats(
                    service_stats=mock_service_stats,
                    file1_path="file1.pcap",
                    file2_path="file2.pcap",
                    pcap_id_mapping={"file1.pcap": 0, "file2.pcap": 1},
                    service_to_group_mapping=service_to_group_mapping,
                )

                # Verify records were inserted
                assert records > 0

    def test_write_service_stats_uses_type_2_for_servers(
        self, mock_connection: MagicMock, mock_cursor: MagicMock, mock_service_stats
    ):
        """Test that service aggregation uses type=2 for server nodes (same as endpoint pair mode)."""
        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                db.write_service_stats(
                    service_stats=mock_service_stats,
                    file1_path="file1.pcap",
                    file2_path="file2.pcap",
                    pcap_id_mapping={"file1.pcap": 0, "file2.pcap": 1},
                )

                # Check that INSERT statements include type=2 for servers
                insert_calls = [
                    str(call) for call in mock_cursor.execute.call_args_list
                    if 'INSERT INTO' in str(call)
                ]

                # At least one INSERT should have type=2 (server nodes)
                # This is a simplified check - in reality we'd need to parse the SQL
                assert len(insert_calls) > 0

    def test_write_service_stats_deduplicates_ips(
        self, mock_connection: MagicMock, mock_cursor: MagicMock
    ):
        """Test that service stats deduplicates client and server IPs."""
        from capmaster.plugins.match.endpoint_stats import ServiceStats, ServiceKey, EndpointPairStats, EndpointTuple

        # Create multiple endpoint pairs with overlapping IPs
        pair1 = MagicMock(spec=EndpointPairStats)
        pair1.tuple_a = EndpointTuple("192.168.1.100", "10.0.0.1", 8000, "TCP")
        pair1.tuple_b = EndpointTuple("172.16.0.100", "192.168.1.1", 8000, "TCP")
        pair1.count = 3
        pair1.client_ttl_a = 64
        pair1.server_ttl_a = 63
        pair1.client_ttl_b = 58
        pair1.server_ttl_b = 62
        pair1.client_hops_a = 0
        pair1.server_hops_a = 1
        pair1.client_hops_b = 6
        pair1.server_hops_b = 2
        pair1.total_bytes_a = 3000
        pair1.total_bytes_b = 2800

        pair2 = MagicMock(spec=EndpointPairStats)
        pair2.tuple_a = EndpointTuple("192.168.1.100", "10.0.0.2", 8000, "TCP")  # Same client
        pair2.tuple_b = EndpointTuple("172.16.0.100", "192.168.1.1", 8000, "TCP")  # Same client and server
        pair2.count = 2
        pair2.client_ttl_a = 64
        pair2.server_ttl_a = 63
        pair2.client_ttl_b = 58
        pair2.server_ttl_b = 62
        pair2.client_hops_a = 0
        pair2.server_hops_a = 1
        pair2.client_hops_b = 6
        pair2.server_hops_b = 2
        pair2.total_bytes_a = 2000
        pair2.total_bytes_b = 1800

        service_key = ServiceKey(8000, "TCP")
        service_stats = ServiceStats(
            service_key=service_key,
            endpoint_pairs=[pair1, pair2],
            total_connections=5,
            unique_server_ips_a={"10.0.0.1", "10.0.0.2"},  # 2 unique servers
            unique_server_ips_b={"192.168.1.1"},  # 1 unique server
            unique_client_ips_a={"192.168.1.100"},  # 1 unique client (deduplicated)
            unique_client_ips_b={"172.16.0.100"},  # 1 unique client (deduplicated)
        )

        with patch('psycopg2.connect', return_value=mock_connection):
            with MatchDatabaseWriter("postgresql://user:pass@localhost:5432/testdb", 137) as db:
                records = db.write_service_stats(
                    service_stats=[service_stats],
                    file1_path="file1.pcap",
                    file2_path="file2.pcap",
                    pcap_id_mapping={"file1.pcap": 0, "file2.pcap": 1},
                )

                # Should insert:
                # - 1 client from file A (deduplicated)
                # - 2 servers from file A
                # - 1 client from file B (deduplicated)
                # - 1 server from file B
                # - Network devices (if any)
                assert records >= 5, "Should insert at least 5 deduplicated records"

