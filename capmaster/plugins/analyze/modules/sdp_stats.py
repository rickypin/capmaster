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
        
        audio_count = media_types.get('audio', 0)
        video_count = media_types.get('video', 0)
        image_count = media_types.get('image', 0)
        secure_count = sum(count for proto, count in protocols.items() if 'SAVP' in proto)
        insecure_sessions = total_messages - secure_count
        security_severity = (
            "High" if insecure_sessions and secure_count == 0 else ("Medium" if insecure_sessions else "Low")
        )

        lines.append("Media Capability Highlights:")
        lines.append("-" * 80)
        lines.append("Observation,Detail")
        if audio_count:
            lines.append(f"Audio sessions,{audio_count}")
        if video_count:
            lines.append(f"Video sessions,{video_count}")
        if image_count:
            lines.append(f"Image/Fax sessions,{image_count}")
        lines.append(f"Secure RTP sessions,{secure_count}")
        lines.append(f"Unsecured RTP sessions,{insecure_sessions} (Severity: {security_severity})")
        lines.append("")

        if messages:
            lines.append("Session Samples:")
            lines.append("-" * 80)
            lines.append("Frame,Source,Destination,Media,Protocols")
            sampled = self.sample_items(messages, limit=5)
            for msg in sampled:
                media_str = '/'.join(msg['media'][:3]) if msg['media'] else 'n/a'
                proto_str = '/'.join(msg['protocols'][:2]) if msg['protocols'] else 'n/a'
                lines.append(
                    f"{msg['frame']},{msg['src']}->{msg['dst']},{media_str},{proto_str}"
                )
            remaining = total_messages - len(sampled)
            if remaining > 0:
                lines.append(f"... {remaining} additional session(s) hidden")

        lines.append("")
        lines.append("=" * 80)

        return '\n'.join(lines) + '\n'

