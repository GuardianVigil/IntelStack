from typing import Dict, List, Optional

def format_virustotal_data(data: Dict) -> Dict:
    """Format VirusTotal response data into a structured table format."""
    if not data or not isinstance(data, dict):
        return {"error": "Invalid data"}
    
    scan_results = data.get("scan_results", {})
    formatted_data = {
        "summary": {
            "total_scans": scan_results.get("total_scans", 0),
            "malicious": scan_results.get("malicious", 0),
            "suspicious": scan_results.get("suspicious", 0),
            "undetected": scan_results.get("undetected", 0),
            "detection_rate": f"{(scan_results.get('malicious', 0) / scan_results.get('total_scans', 1)) * 100:.1f}%"
        },
        "detections": []
    }

    # Convert scan results to table format
    for engine, result in scan_results.get("scan_results", {}).items():
        formatted_data["detections"].append({
            "engine": engine,
            "category": result.get("category", "unknown"),
            "result": result.get("result", "N/A"),
            "engine_version": result.get("engine_version", "N/A"),
            "engine_update": result.get("engine_update", "N/A")
        })

    return formatted_data

def format_hybrid_analysis_data(data: Dict) -> Dict:
    """Format Hybrid Analysis response data into a structured table format."""
    if not data or not isinstance(data, dict):
        return {"error": "Invalid data"}
    
    formatted_data = {
        "summary": {
            "threat_score": data.get("threat_score", 0),
            "verdict": data.get("verdict", "unknown"),
            "vx_family": data.get("vx_family", "N/A"),
            "type": data.get("type", "N/A"),
            "size": data.get("size", 0)
        },
        "scanners": []
    }

    # Convert scanner results to table format
    for scanner in data.get("scanners", []):
        formatted_data["scanners"].append({
            "name": scanner.get("name", "N/A"),
            "status": scanner.get("status", "unknown"),
            "positives": scanner.get("positives", 0),
            "total": scanner.get("total", 0),
            "percent": f"{scanner.get('percent', 0)}%"
        })

    return formatted_data

def format_filescan_data(data: Dict) -> Dict:
    """Format FileScan response data into a structured table format."""
    if not data or not isinstance(data, dict):
        return {"error": "Invalid data"}
    
    scan_results = data.get("scan_results", {})
    formatted_data = {
        "summary": {
            "overall_status": scan_results.get("overall_status", "unknown"),
            "total_engines": scan_results.get("total_engines", 0),
            "total_detected": scan_results.get("total_detected", 0),
            "detection_rate": f"{(scan_results.get('total_detected', 0) / scan_results.get('total_engines', 1)) * 100:.1f}%"
        },
        "detections": []
    }

    # Convert scan details to table format
    scan_details = scan_results.get("scan_details", {})
    for engine, result in scan_details.items():
        formatted_data["detections"].append({
            "engine": engine,
            "threat_found": result.get("threat_found", "N/A"),
            "scan_time": result.get("scan_time", "N/A"),
            "def_time": result.get("def_time", "N/A")
        })

    return formatted_data

def format_platform_data(platform_name: str, data: Dict) -> Dict:
    """Format platform data into a standardized structure."""
    if not data:
        return {"error": "No data available"}

    formatted_data = {
        "summary": {},
        "detections": [],
        "malware_info": {},
        "threat_intel": {}
    }

    try:
        if platform_name == "virustotal":
            if "scan_results" in data:
                vt_data = data["scan_results"]
                # Summary
                formatted_data["summary"] = {
                    "total_scans": sum(vt_data.get("last_analysis_stats", {}).values()),
                    "malicious": vt_data.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": vt_data.get("last_analysis_stats", {}).get("suspicious", 0),
                    "undetected": vt_data.get("last_analysis_stats", {}).get("undetected", 0),
                    "file_type": vt_data.get("file_type"),
                    "reputation": vt_data.get("reputation")
                }
                # Detections
                for engine, result in vt_data.get("scan_results", {}).items():
                    formatted_data["detections"].append({
                        "engine": engine,
                        "category": result.get("category"),
                        "result": result.get("result"),
                        "method": result.get("method")
                    })

        elif platform_name == "hybrid_analysis":
            # Summary
            formatted_data["summary"] = {
                "threat_score": data.get("threat_score"),
                "verdict": data.get("verdict"),
                "file_type": data.get("type"),
                "size": data.get("size"),
                "submitted_at": data.get("submitted_at"),
                "last_analysis": data.get("last_multi_scan")
            }
            # Malware Info
            formatted_data["malware_info"] = {
                "vx_family": data.get("vx_family"),
                "tags": data.get("tags", []),
                "type_tags": data.get("type_short", [])
            }
            # Process scanner results
            if "scanners" in data:
                for scanner in data["scanners"]:
                    formatted_data["detections"].append({
                        "engine": scanner.get("name"),
                        "category": scanner.get("status"),
                        "result": f"{scanner.get('positives', 0)}/{scanner.get('total', 0)} ({scanner.get('percent', 0)}%)",
                        "method": "scan"
                    })

        elif platform_name == "filescan":
            # Summary
            formatted_data["summary"] = {
                "verdict": data.get("overall_verdict"),
                "fuzzy_hash": data.get("fuzzyhash", {}).get("hash"),
                "total_engines": data.get("total_engines", 0),
                "total_detected": data.get("total_detected", 0)
            }
            # Process scan results
            if "scan_details" in data:
                for engine, result in data["scan_details"].items():
                    formatted_data["detections"].append({
                        "engine": engine,
                        "category": "malicious" if result.get("scan_result_i") == 1 else "clean",
                        "result": result.get("threat_found") or "clean",
                        "method": "scan"
                    })

        elif platform_name == "metadefender":
            if "scan_results" in data:
                scan_results = data["scan_results"]
                # Summary
                formatted_data["summary"] = {
                    "overall_status": scan_results.get("overall_status"),
                    "total_engines": scan_results.get("total_engines", 0),
                    "total_detected": scan_results.get("total_detected", 0),
                    "scan_time": scan_results.get("scan_time")
                }
                # Process scan details
                if "scan_details" in scan_results:
                    for engine, result in scan_results["scan_details"].items():
                        formatted_data["detections"].append({
                            "engine": engine,
                            "category": "malicious" if result.get("scan_result_i") == 1 else "clean",
                            "result": result.get("threat_found") or "clean",
                            "method": "scan"
                        })

        elif platform_name == "malwarebazaar":
            if "data" in data and data["data"]:
                mb_data = data["data"][0]
                # Summary
                formatted_data["summary"] = {
                    "file_type": mb_data.get("file_type"),
                    "file_size": mb_data.get("file_size"),
                    "first_seen": mb_data.get("first_seen"),
                    "last_seen": mb_data.get("last_seen")
                }
                # Malware Info
                formatted_data["malware_info"] = {
                    "signature": mb_data.get("signature"),
                    "tags": mb_data.get("tags", []),
                    "reporter": mb_data.get("reporter")
                }

        elif platform_name == "threatfox":
            if "scan_results" in data:
                scan_results = data["scan_results"]
                # Summary
                formatted_data["summary"] = {
                    "total_matches": scan_results.get("total_matches", 0),
                    "found": data.get("found", False)
                }
                # Threat Intel
                if "matches" in scan_results:
                    for match in scan_results["matches"]:
                        formatted_data["threat_intel"] = {
                            "malware": match.get("malware"),
                            "threat_type": match.get("threat_type"),
                            "confidence_level": match.get("confidence_level"),
                            "tags": match.get("tags", [])
                        }

    except Exception as e:
        formatted_data["error"] = str(e)

    return formatted_data

def calculate_confidence_score(platforms_data: Dict) -> float:
    """Calculate confidence score based on platform results."""
    if not platforms_data:
        return 0

    total_engines = 0
    total_detections = 0
    platform_weights = {
        'virustotal': 0.4,
        'hybrid_analysis': 0.3,
        'filescan': 0.3
    }

    weighted_scores = []

    # Process VirusTotal
    if 'virustotal' in platforms_data:
        vt_data = platforms_data['virustotal']
        if 'summary' in vt_data:
            total_scans = vt_data['summary'].get('total_scans', 0)
            malicious = vt_data['summary'].get('malicious', 0)
            if total_scans > 0:
                score = (malicious / total_scans) * 100
                weighted_scores.append(score * platform_weights['virustotal'])
                total_engines += total_scans
                total_detections += malicious

    # Process Hybrid Analysis
    if 'hybrid_analysis' in platforms_data:
        ha_data = platforms_data['hybrid_analysis']
        if 'summary' in ha_data:
            threat_score = ha_data['summary'].get('threat_score', 0)
            if threat_score is not None:
                weighted_scores.append(threat_score * platform_weights['hybrid_analysis'])

    # Process FileScan
    if 'filescan' in platforms_data:
        fs_data = platforms_data['filescan']
        if 'summary' in fs_data:
            total = fs_data['summary'].get('total_engines', 0)
            detected = fs_data['summary'].get('total_detected', 0)
            if total > 0:
                score = (detected / total) * 100
                weighted_scores.append(score * platform_weights['filescan'])
                total_engines += total
                total_detections += detected

    # Calculate final confidence score
    if weighted_scores:
        # Base confidence on weighted platform scores
        platform_confidence = sum(weighted_scores)
        
        # Adjust confidence based on number of engines
        engine_factor = min(total_engines / 50, 1)  # Cap at 50 engines for 100%
        
        # Final confidence is average of platform confidence and engine coverage
        final_confidence = (platform_confidence + (engine_factor * 100)) / 2
        
        return min(max(final_confidence, 0), 100)
    
    return 0
