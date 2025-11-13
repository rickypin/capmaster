"""Core connection processing module.

This module provides shared functionality for TCP connection extraction,
matching, and scoring. It is used by multiple plugins (match, compare, etc.)
to avoid code duplication.
"""

from capmaster.core.connection.models import (
    ConnectionBuilder,
    FiveTupleConnectionBuilder,
    TcpConnection,
    TcpPacket,
)
from capmaster.core.connection.extractor import TcpFieldExtractor
from capmaster.core.connection.connection_extractor import extract_connections_from_pcap
from capmaster.core.connection.matcher import BucketStrategy, ConnectionMatch, ConnectionMatcher, MatchMode
from capmaster.core.connection.scorer import ConnectionScorer, MatchScore
from capmaster.core.connection.f5_matcher import F5Matcher, F5ConnectionPair
from capmaster.core.connection.tls_matcher import TlsMatcher, TlsConnectionPair

__all__ = [
    # Models
    "TcpConnection",
    "TcpPacket",
    "ConnectionBuilder",
    "FiveTupleConnectionBuilder",
    # Extractor
    "TcpFieldExtractor",
    "extract_connections_from_pcap",
    # Matcher
    "ConnectionMatcher",
    "ConnectionMatch",
    "BucketStrategy",
    "MatchMode",
    # Scorer
    "ConnectionScorer",
    "MatchScore",
    # F5 Matcher
    "F5Matcher",
    "F5ConnectionPair",
    # TLS Matcher
    "TlsMatcher",
    "TlsConnectionPair",
]

