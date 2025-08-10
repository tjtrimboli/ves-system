"""JSON format output formatter"""

import json
import sys
from dataclasses import asdict
from typing import List

from ...core.models import VulnerabilityMetrics


class JSONFormatter:
    """JSON format output formatter"""
    
    @staticmethod
    def format_single(metrics: VulnerabilityMetrics) -> str:
        """Format single result as JSON"""
        data = asdict(metrics)
        
        # Convert datetime objects to strings
        if data.get('published_date') and metrics.published_date:
            data['published_date'] = metrics.published_date.isoformat()
        if data.get('last_modified') and metrics.last_modified:
            data['last_modified'] = metrics.last_modified.isoformat()
        
        # Convert enum to string
        data['severity'] = metrics.severity.value
        
        return json.dumps(data, indent=2)
    
    @staticmethod
    def format_bulk(results: List[VulnerabilityMetrics]) -> str:
        """Format multiple results as JSON array"""
        data_list = []
        
        for result in results:
            data = asdict(result)
            
            # Convert datetime objects to strings
            if data.get('published_date') and result.published_date:
                data['published_date'] = result.published_date.isoformat()
            if data.get('last_modified') and result.last_modified:
                data['last_modified'] = result.last_modified.isoformat()
            
            # Convert enum to string
            data['severity'] = result.severity.value
            data_list.append(data)
        
        return json.dumps(data_list, indent=2)
    
    @staticmethod
    def save_bulk(results: List[VulnerabilityMetrics], output_path: str = None):
        """Save bulk results to JSON file or stdout"""
        json_output = JSONFormatter.format_bulk(results)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(json_output)
            print(f"Results saved to {output_path}")
        else:
            print(json_output)
