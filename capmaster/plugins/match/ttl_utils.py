"""TTL (Time To Live) utilities for network hop analysis.

This module provides utilities for analyzing TTL values to determine
the number of network hops between the packet source and capture point.

The logic is based on common initial TTL values used by different operating systems:
- 64: Linux/Unix systems
- 128: Windows systems
- 255: Some network devices

By comparing the observed TTL with these standard values, we can estimate
how many routers/hops the packet traversed.
"""

from __future__ import annotations


class TtlDelta:
    """
    Calculate TTL delta (number of hops) from observed TTL value.
    
    The delta represents the number of network hops between the packet
    source and the capture point.
    """
    
    def __init__(self, ttl: int):
        """
        Initialize TTL delta calculator.
        
        Args:
            ttl: Observed TTL value from packet
        """
        if ttl <= 0:
            self.delta = 0
            self.initial_ttl = 0
        elif ttl <= 64:
            self.delta = 64 - ttl
            self.initial_ttl = 64
        elif ttl <= 128:
            self.delta = 128 - ttl
            self.initial_ttl = 128
        else:
            self.delta = 255 - ttl
            self.initial_ttl = 255
    
    @property
    def hops(self) -> int:
        """
        Get the number of network hops.
        
        Returns:
            Number of hops (0 means direct connection or unknown)
        """
        return self.delta
    
    def has_intermediate_device(self) -> bool:
        """
        Check if there are intermediate network devices.
        
        Returns:
            True if delta > 0 (packet passed through routers)
        """
        return self.delta > 0
    
    def __repr__(self) -> str:
        """String representation."""
        return f"TtlDelta(ttl={self.initial_ttl - self.delta}, initial={self.initial_ttl}, hops={self.delta})"
    
    def __eq__(self, other: object) -> bool:
        """Equality comparison."""
        if not isinstance(other, TtlDelta):
            return NotImplemented
        return self.delta == other.delta
    
    def __hash__(self) -> int:
        """Hash for use in sets/dicts."""
        return hash(self.delta)


def calculate_hops(ttl: int) -> int:
    """
    Calculate the number of network hops from TTL value.
    
    This is a convenience function that creates a TtlDelta and returns the hops.
    
    Args:
        ttl: Observed TTL value from packet
        
    Returns:
        Number of network hops (0 if TTL is 0 or invalid)
        
    Examples:
        >>> calculate_hops(64)  # Direct connection, Linux system
        0
        >>> calculate_hops(60)  # 4 hops from Linux system
        4
        >>> calculate_hops(128)  # Direct connection, Windows system
        0
        >>> calculate_hops(120)  # 8 hops from Windows system
        8
        >>> calculate_hops(255)  # Direct connection, network device
        0
        >>> calculate_hops(240)  # 15 hops from network device
        15
    """
    if ttl <= 0:
        return 0
    return TtlDelta(ttl).hops


def most_common_hops(ttl_values: list[int]) -> int:
    """
    Calculate the most common hop count from a list of TTL values.
    
    This function:
    1. Converts each TTL to hop count
    2. Finds the most frequently occurring hop count
    3. Returns that hop count
    
    Args:
        ttl_values: List of observed TTL values
        
    Returns:
        Most common hop count (0 if list is empty)
        
    Examples:
        >>> most_common_hops([64, 64, 64, 63])  # Mostly direct, one with 1 hop
        0
        >>> most_common_hops([60, 60, 61, 64])  # Mostly 4 hops
        4
    """
    if not ttl_values:
        return 0
    
    from collections import Counter
    
    # Convert TTLs to hops
    hops_list = [calculate_hops(ttl) for ttl in ttl_values]
    
    # Find most common
    return Counter(hops_list).most_common(1)[0][0]


def analyze_ttl_info(client_ttls: list[int], server_ttls: list[int]) -> dict[str, int]:
    """
    Analyze TTL information for both client and server.
    
    Args:
        client_ttls: List of TTL values from client packets
        server_ttls: List of TTL values from server packets
        
    Returns:
        Dictionary with keys:
        - 'client_hops': Most common hop count for client
        - 'server_hops': Most common hop count for server
        - 'client_has_device': Whether client has intermediate devices (bool as int)
        - 'server_has_device': Whether server has intermediate devices (bool as int)
        
    Examples:
        >>> analyze_ttl_info([64, 64, 64], [60, 60, 61])
        {'client_hops': 0, 'server_hops': 4, 'client_has_device': 0, 'server_has_device': 1}
    """
    client_hops = most_common_hops(client_ttls)
    server_hops = most_common_hops(server_ttls)
    
    return {
        'client_hops': client_hops,
        'server_hops': server_hops,
        'client_has_device': 1 if client_hops > 0 else 0,
        'server_has_device': 1 if server_hops > 0 else 0,
    }

