import asyncio
import time
import requests
from typing import Dict, Any, Optional
from django.core.files.uploadedfile import UploadedFile
from main.models import APIKey, SandboxAnalysis
from .data_formatter import format_virustotal_data

class VirusTotalProcessor:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.api_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}

    async def process_file(self, file: UploadedFile, analysis_obj: SandboxAnalysis) -> Dict[str, Any]:
        """
        Process a file through VirusTotal asynchronously
        """
        try:
            # Upload file
            analysis_id = await self._upload_file(file)
            if not analysis_id:
                raise Exception("Failed to upload file to VirusTotal")

            # Update analysis object with ID
            analysis_obj.analysis_id = analysis_id
            analysis_obj.status = 'analyzing'
            analysis_obj.save()

            # Wait for analysis to complete
            report = await self._wait_for_analysis(analysis_id)
            if not report:
                raise Exception("Analysis timed out or failed")

            # Get file hash for behavior analysis
            file_hash = report.get('meta', {}).get('file_info', {}).get('sha256')
            if not file_hash:
                raise Exception("Could not get file hash from report")

            # Get behavior summary
            behavior = await self._get_behavior_summary(file_hash)

            # Format data
            formatted_data = format_virustotal_data({
                'analysis_report': report,
                'behavior_summary': behavior
            })

            # Update analysis object
            analysis_obj.status = 'completed'
            analysis_obj.result = formatted_data
            analysis_obj.save()

            return formatted_data

        except Exception as e:
            analysis_obj.status = 'failed'
            analysis_obj.error_message = str(e)
            analysis_obj.save()
            raise

    async def _upload_file(self, file: UploadedFile) -> Optional[str]:
        """Upload file to VirusTotal"""
        try:
            files = {"file": (file.name, file)}
            response = requests.post(
                f"{self.api_url}/files",
                files=files,
                headers=self.headers
            )
            response.raise_for_status()
            return response.json().get('data', {}).get('id')
        except Exception as e:
            print(f"Error uploading file: {e}")
            return None

    async def _wait_for_analysis(self, analysis_id: str, max_attempts: int = 10) -> Optional[Dict]:
        """Wait for analysis to complete"""
        for attempt in range(max_attempts):
            try:
                response = requests.get(
                    f"{self.api_url}/analyses/{analysis_id}",
                    headers=self.headers
                )
                response.raise_for_status()
                result = response.json()
                
                if result.get('data', {}).get('attributes', {}).get('status') == 'completed':
                    return result
                
                # Wait before next attempt
                await asyncio.sleep(15)
            except Exception as e:
                print(f"Error checking analysis status: {e}")
                await asyncio.sleep(15)
        
        return None

    async def _get_behavior_summary(self, file_hash: str) -> Optional[Dict]:
        """Get behavior summary for a file"""
        try:
            response = requests.get(
                f"{self.api_url}/files/{file_hash}/behaviour_summary",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error getting behavior summary: {e}")
            return None

async def process_sandbox_analysis(file: UploadedFile, analysis_obj: SandboxAnalysis) -> Dict[str, Any]:
    """
    Main entry point for processing sandbox analysis
    """
    # Get API key from database
    api_key = APIKey.objects.filter(
        platform='virustotal',
        is_active=True
    ).first()

    if not api_key:
        raise Exception("No active VirusTotal API key found")

    processor = VirusTotalProcessor(api_key.api_key)
    return await processor.process_file(file, analysis_obj)