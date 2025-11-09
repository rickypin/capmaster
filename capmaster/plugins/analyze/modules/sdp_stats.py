"""SDP (Session Description Protocol) statistics module."""

from __future__ import annotations

from pathlib import Path
from collections import Counter, defaultdict

from capmaster.plugins.analyze.modules import register_module
from capmaster.plugins.analyze.modules.base import AnalysisModule


@register_module
class SdpStatsModule(AnalysisModule):
    """Generate SDP protocol statistics.
    
    Analyzes Session Description Protocol (SDP) messages to extract:
    - Media types (audio, video, image, application)
    - Media formats and codecs
    - Transport protocols (RTP/AVP, RTP/SAVP, udptl)
    - Port allocations
    - Media capability negotiations
    
    SDP is used to describe multimedia sessions for session announcement,
    session invitation, and parameter negotiation. This module helps analyze
    VoIP call setup and media capabilities.
    """

    @property
    def name(self) -> str:
        """Module name."""
        return "sdp_stats"

    @property
    def output_suffix(self) -> str:
        """Output file suffix."""
        return "sdp-stats.txt"

    @property
    def required_protocols(self) -> set[str]:
        """Required protocols."""
        return {"sdp"}

    def build_tshark_args(self, input_file: Path) -> list[str]:
        """
        Build tshark command arguments.

        Args:
            input_file: Path to input PCAP file

        Returns:
            List of tshark arguments for SDP analysis
        """
        return [
            "-Y", "sdp",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.len",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "sdp.media",
            "-e", "sdp.media.port",
            "-e", "sdp.media.proto",
            "-e", "sdp.media.format",
        ]

    def post_process(self, tshark_output: str, output_format: str = "txt") -> str:
        """
        Post-process SDP messages to generate statistics.
        
        Args:
            tshark_output: Raw tshark output
            output_format: Output format ("txt" or "md", default: "txt")
            
        Returns:
            Formatted output with SDP statistics
        """
        if not tshark_output.strip():
            return "No SDP messages found\n"
        
        lines = []
        lines.append("=" * 80)
        lines.append("SDP Statistics")
        lines.append("=" * 80)
        lines.append("")
        
        # Parse SDP messages
        messages = []
        media_types = Counter()
        protocols = Counter()
        codecs = Counter()
        ports = []
        
        for line in tshark_output.strip().split('\n'):
            parts = line.split('\t')
            if len(parts) < 8:
                continue
            
            frame_num = parts[0]
            frame_len = parts[1]
            src_ip = parts[2]
            dst_ip = parts[3]
            media = parts[4]
            port = parts[5]
            proto = parts[6]
            formats = parts[7]
            
            # Parse media types (can be multiple comma-separated)
            media_list = [m.strip() for m in media.split(',') if m.strip()]
            proto_list = [p.strip() for p in proto.split(',') if p.strip()]
            port_list = [p.strip() for p in port.split(',') if p.strip()]
            format_list = [f.strip() for f in formats.split(',') if f.strip()]
            
            # Count media types
            for m in media_list:
                media_types[m] += 1
            
            # Count protocols
            for p in proto_list:
                protocols[p] += 1
            
            # Count codecs/formats
            for f in format_list:
                # Skip numeric-only formats (RTP payload types)
                if not f.isdigit():
                    codecs[f] += 1
            
            # Collect ports
            for p in port_list:
                if p and p != '0':
                    try:
                        ports.append(int(p))
                    except ValueError:
                        pass
            
            messages.append({
                'frame': frame_num,
                'size': int(frame_len) if frame_len else 0,
                'src': src_ip,
                'dst': dst_ip,
                'media': media_list,
                'protocols': proto_list,
                'formats': format_list,
            })
        
        total_messages = len(messages)
        
        # Summary
        lines.append("Summary:")
        lines.append("-" * 80)
        lines.append(f"  Total SDP Messages:      {total_messages}")
        lines.append(f"  Unique Media Types:      {len(media_types)}")
        lines.append(f"  Unique Protocols:        {len(protocols)}")
        lines.append(f"  Unique Codecs:           {len(codecs)}")
        lines.append("")
        
        # Media type distribution
        if media_types:
            lines.append("Media Types:")
            lines.append("-" * 80)
            lines.append(f"{'Media Type':<20} {'Count':<10} {'Percentage':<12}")
            lines.append("-" * 80)
            
            total_media = sum(media_types.values())
            for media, count in media_types.most_common():
                percentage = (count / total_media) * 100
                lines.append(f"{media:<20} {count:<10} {percentage:>5.1f}%")
            
            lines.append("")
        
        # Protocol distribution
        if protocols:
            lines.append("Transport Protocols:")
            lines.append("-" * 80)
            lines.append(f"{'Protocol':<20} {'Count':<10} {'Percentage':<12}")
            lines.append("-" * 80)
            
            total_proto = sum(protocols.values())
            for proto, count in protocols.most_common():
                percentage = (count / total_proto) * 100
                
                # Add description
                proto_desc = proto
                if 'RTP/AVP' in proto:
                    proto_desc += ' (RTP Audio/Video Profile)'
                elif 'RTP/SAVP' in proto:
                    proto_desc += ' (Secure RTP)'
                elif 'udptl' in proto:
                    proto_desc += ' (Fax over IP)'
                
                lines.append(f"{proto_desc:<40} {count:<10} {percentage:>5.1f}%")
            
            lines.append("")
        
        # Codec distribution
        if codecs:
            lines.append("Top Codecs/Formats:")
            lines.append("-" * 80)
            lines.append(f"{'Codec/Format':<40} {'Count':<10}")
            lines.append("-" * 80)
            
            for codec, count in codecs.most_common(15):
                lines.append(f"{codec:<40} {count:<10}")
            
            lines.append("")
        
        # Port analysis
        if ports:
            lines.append("Port Allocation:")
            lines.append("-" * 80)
            
            unique_ports = len(set(ports))
            min_port = min(ports)
            max_port = max(ports)
            
            lines.append(f"  Total Ports Allocated:   {len(ports)}")
            lines.append(f"  Unique Ports:            {unique_ports}")
            lines.append(f"  Port Range:              {min_port} - {max_port}")
            
            # Check for common port ranges
            rtp_range = sum(1 for p in ports if 16384 <= p <= 32767)
            if rtp_range > 0:
                lines.append(f"  RTP Range (16384-32767): {rtp_range} ports")
            
            lines.append("")
        
        # Media capability analysis
        lines.append("Media Capability Analysis:")
        lines.append("-" * 80)
        
        audio_count = media_types.get('audio', 0)
        video_count = media_types.get('video', 0)
        image_count = media_types.get('image', 0)
        
        if audio_count > 0:
            lines.append(f"  ✓ Audio support: {audio_count} session(s)")
        if video_count > 0:
            lines.append(f"  ✓ Video support: {video_count} session(s)")
        if image_count > 0:
            lines.append(f"  ✓ Image/Fax support: {image_count} session(s)")
        
        # Check for secure protocols
        secure_count = sum(count for proto, count in protocols.items() if 'SAVP' in proto)
        if secure_count > 0:
            lines.append(f"  ✓ Secure RTP (SRTP): {secure_count} session(s)")
        
        lines.append("")
        
        # Session details
        lines.append("Session Details:")
        lines.append("-" * 80)
        lines.append(f"{'Frame':<8} {'Size':<8} {'Source IP':<18} {'Dest IP':<18} {'Media Types':<20}")
        lines.append("-" * 80)
        
        for msg in messages[:10]:  # Show first 10
            media_str = ', '.join(msg['media'][:3])  # Show first 3 media types
            lines.append(f"{msg['frame']:<8} {msg['size']:<8} {msg['src']:<18} "
                        f"{msg['dst']:<18} {media_str:<20}")
        
        if len(messages) > 10:
            lines.append(f"... and {len(messages) - 10} more session(s)")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("")
        lines.append("SDP Protocol Notes:")
        lines.append("  - SDP describes multimedia sessions for VoIP calls")
        lines.append("  - Typically carried in SIP INVITE and 200 OK messages")
        lines.append("  - Media Types:")
        lines.append("    * audio - Voice communication")
        lines.append("    * video - Video communication")
        lines.append("    * image - Fax and image transmission")
        lines.append("    * application - Application data")
        lines.append("  - Common Protocols:")
        lines.append("    * RTP/AVP - RTP Audio/Video Profile (standard)")
        lines.append("    * RTP/SAVP - Secure RTP (encrypted)")
        lines.append("    * udptl - Fax over IP (T.38)")
        lines.append("  - Common Audio Codecs:")
        lines.append("    * G.711 (PCMU/PCMA) - Standard quality, high bandwidth")
        lines.append("    * G.729 - Good quality, low bandwidth")
        lines.append("    * G.722 - Wideband audio")
        lines.append("    * Opus - Modern adaptive codec")
        lines.append("")
        lines.append("=" * 80)
        
        return '\n'.join(lines) + '\n'

