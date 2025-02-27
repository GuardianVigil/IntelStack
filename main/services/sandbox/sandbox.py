import os
import time
import json
import requests
from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.core.files.uploadedfile import UploadedFile
from main.models import APIKey
from main.services.encryption import decrypt_api_key
from datetime import datetime
import tempfile

# Constants
MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB in bytes
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
ALLOWED_FILE_TYPES = {'.exe', '.dll', '.pdf', '.doc', '.docx', '.xls', '.xlsx'}

def save_debug_output(data, prefix='virustotal'):
    """Save debug output to a file"""
    # Create a single debug file for the entire session
    output_dir = os.path.join(os.path.dirname(__file__), 'debug_output')
    os.makedirs(output_dir, exist_ok=True)
    
    # Use a timestamp at the module level to keep one file per session
    global _debug_session_timestamp
    if not hasattr(save_debug_output, '_debug_session_timestamp'):
        save_debug_output._debug_session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create a single debug file for the entire session
    output_file = os.path.join(output_dir, f'virustotal_debug_{save_debug_output._debug_session_timestamp}.txt')
    
    # Format the data with timestamp and prefix
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_content = f"\n\n{'='*80}\n[{timestamp}] {prefix}\n{'='*80}\n"
    
    if isinstance(data, dict) or isinstance(data, list):
        output_content += json.dumps(data, indent=4)
    else:
        output_content += str(data)
    
    # Append to the file
    with open(output_file, 'a') as f:
        f.write(output_content)
    
    print(f"Saved {prefix} debug output to: {output_file}")

def format_analysis_results(analysis_data, behavior_data=None):
    """Format analysis results for frontend display"""
    try:
        # Save complete raw data for debugging
        save_debug_output(analysis_data, 'complete_analysis_data')
        if behavior_data:
            save_debug_output(behavior_data, 'complete_behavior_data')
        
        # Extract data from analysis response
        attributes = analysis_data.get('data', {}).get('attributes', {})
        stats = attributes.get('stats', {})
        
        # Calculate threat score (0-100)
        total_scans = sum(stats.values()) if stats else 0
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        threat_score = ((malicious + suspicious) / total_scans * 100) if total_scans > 0 else 0

        # Get file info from meta data
        file_info = analysis_data.get('meta', {}).get('file_info', {})
        
        # If file_info is empty, try to get it from attributes
        if not file_info:
            file_info = {
                'sha256': attributes.get('sha256', 'N/A'),
                'size': attributes.get('size', 0),
                'type': attributes.get('type_description', 'Unknown')
            }
        
        # Format behavior data
        process_count = 0
        network_count = 0
        file_count = 0
        registry_count = 0
        
        if behavior_data:
            behavior_attrs = behavior_data.get('data', {})
            
            # Count processes
            processes = behavior_attrs.get('processes', [])
            process_count = len(processes)
            
            # Count network connections
            network = behavior_attrs.get('network_connections', [])
            network_count = len(network)
            
            # Count file operations
            files_written = behavior_attrs.get('files_written', [])
            files_opened = behavior_attrs.get('files_opened', [])
            file_count = len(files_written) + len(files_opened)
            
            # Count registry operations
            registry_keys = behavior_attrs.get('registry_keys_set', [])
            registry_count = len(registry_keys)
        
        # Create formatted result
        formatted_result = {
            'quick_analysis': {
                'threat_score': round(threat_score, 1),
                'file_type': file_info.get('type', 'Unknown'),
                'file_size': file_info.get('size', 0),
                'sha256': file_info.get('sha256', 'N/A'),
                'detection_stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_scans': total_scans
                }
            },
            'behavior_summary': {
                'process_count': process_count,
                'network_count': network_count,
                'file_count': file_count,
                'registry_count': registry_count
            },
            'detailed_analysis': {}  # We'll add more detailed data here if needed
        }
        
        # Save the formatted results for debugging
        save_debug_output(formatted_result, 'formatted_result')
        
        return formatted_result
    except Exception as e:
        print(f"Error formatting results: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'status': 'error',
            'error': f'Failed to format analysis results: {str(e)}'
        }

def analyze_file(file):
    """Analyze a file using VirusTotal v3 API"""
    temp_file = None
    try:
        # Save debug info about the request
        save_debug_output({
            'file_name': file.name,
            'file_size': file.size,
            'content_type': file.content_type
        }, 'request_info')

        # Validate file size
        if file.size > MAX_FILE_SIZE:
            return {
                'status': 'error',
                'error': f'File size exceeds maximum limit of {MAX_FILE_SIZE // (1024*1024)}MB'
            }

        # Validate file type
        file_ext = os.path.splitext(file.name)[1].lower()
        if file_ext not in ALLOWED_FILE_TYPES:
            return {
                'status': 'error',
                'error': f'File type {file_ext} is not allowed'
            }

        # Get API key
        api_key = APIKey.objects.filter(platform='virustotal').first()
        if not api_key:
            return {
                'status': 'error',
                'error': 'VirusTotal API key not found'
            }

        # Decrypt API key
        decrypted_key = decrypt_api_key(api_key.encrypted_api_key)
        
        # Save file temporarily
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        for chunk in file.chunks():
            temp_file.write(chunk)
        temp_file.close()

        headers = {
            'accept': 'application/json',
            'x-apikey': decrypted_key
        }

        # Upload file to VirusTotal
        print("Uploading file to VirusTotal...")
        with open(temp_file.name, 'rb') as file_obj:
            files = {'file': (file.name, file_obj)}
            upload_response = requests.post(
                f"{VIRUSTOTAL_API_URL}/files",
                files=files,
                headers=headers
            )

        if upload_response.status_code != 200:
            save_debug_output(upload_response.text, 'upload_error_raw')
            try:
                save_debug_output(upload_response.json(), 'upload_error_json')
            except:
                pass
            return {
                'status': 'error',
                'error': f'Failed to upload file: {upload_response.text}'
            }

        upload_data = upload_response.json()
        save_debug_output(upload_data, 'upload_success')
        
        analysis_id = upload_data.get('data', {}).get('id')
        if not analysis_id:
            return {
                'status': 'error',
                'error': 'Failed to get analysis ID from VirusTotal'
            }

        # Poll for analysis completion with longer wait times
        max_retries = 20  # Increased to 20 attempts
        retry_delay = 30  # Increased to 30 seconds
        
        for attempt in range(max_retries):
            print(f"Getting analysis results (attempt {attempt + 1}/{max_retries})...")
            
            # Wait before checking - this gives VirusTotal time to process
            if attempt > 0:  # Don't wait on the first attempt
                print(f"Waiting {retry_delay} seconds before next check...")
                time.sleep(retry_delay)
            
            analysis_response = requests.get(
                f"{VIRUSTOTAL_API_URL}/analyses/{analysis_id}",
                headers=headers
            )
            
            if analysis_response.status_code != 200:
                save_debug_output(analysis_response.text, f'analysis_error_raw_{attempt}')
                try:
                    save_debug_output(analysis_response.json(), f'analysis_error_json_{attempt}')
                except:
                    pass
                continue
                
            analysis_data = analysis_response.json()
            save_debug_output(analysis_data, f'analysis_response_{attempt}')
            
            status = analysis_data.get('data', {}).get('attributes', {}).get('status')
            print(f"Analysis status: {status}")
            
            if status == 'completed':
                # Get behavior data
                file_id = analysis_data.get('meta', {}).get('file_info', {}).get('sha256')
                behavior_data = None
                
                if file_id:
                    print(f"Getting behavior data for file: {file_id}")
                    behavior_response = requests.get(
                        f"{VIRUSTOTAL_API_URL}/files/{file_id}/behaviour_summary",
                        headers=headers
                    )
                    if behavior_response.status_code == 200:
                        behavior_data = behavior_response.json()
                        save_debug_output(behavior_data, 'behavior_data')
                    else:
                        save_debug_output(behavior_response.text, 'behavior_error_raw')
                        try:
                            save_debug_output(behavior_response.json(), 'behavior_error_json')
                        except:
                            pass
                
                # Format and return results
                results = format_analysis_results(analysis_data, behavior_data)
                save_debug_output(results, 'final_results')
                return {
                    'status': 'completed',
                    'results': results
                }
            
            # If status is "queued", we need to wait longer
            if status == "queued" or status == "in-progress":
                print(f"Analysis is {status}, waiting longer...")
                # Continue to next attempt
        
        # If we've reached here, we've timed out
        print("Analysis timed out after maximum attempts")
        return {
            'status': 'error',
            'error': f'Analysis timed out after {max_retries} attempts. VirusTotal may be experiencing high load or the file may be in a long queue. Please try again later.'
        }
    except requests.exceptions.RequestException as e:
        print(f"Request error: {str(e)}")
        return {
            'status': 'error',
            'error': f'Network error: {str(e)}'
        }
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {str(e)}")
        return {
            'status': 'error',
            'error': 'Invalid response from VirusTotal'
        }
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {
            'status': 'error',
            'error': f'Internal error: {str(e)}'
        }
    finally:
        # Clean up temp file
        if temp_file and os.path.exists(temp_file.name):
            try:
                os.unlink(temp_file.name)
            except Exception as e:
                print(f"Error removing temp file: {str(e)}")

def handle_sandbox_analysis(request):
    """Handle sandbox analysis request"""
    if request.method != 'POST':
        return JsonResponse({
            'status': 'error',
            'error': 'Only POST method is allowed'
        }, status=405)

    # Check if this is an AJAX request
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    file = request.FILES.get('file')
    if not file:
        return JsonResponse({
            'status': 'error',
            'error': 'No file provided'
        }, status=400)

    results = analyze_file(file)
    
    # Save the final results for debugging
    save_debug_output(results, 'final_response')
    
    if results.get('status') == 'error':
        if is_ajax:
            return JsonResponse(results, status=500)
        else:
            # For non-AJAX requests, redirect back to the sandbox page with an error message
            from django.shortcuts import redirect
            from django.contrib import messages
            messages.error(request, results.get('error', 'An error occurred during analysis'))
            return redirect('sandbox')
    
    # For AJAX requests, return JSON
    if is_ajax:
        return JsonResponse(results)
    else:
        # For non-AJAX requests, redirect back to the sandbox page with a success message
        from django.shortcuts import redirect
        from django.contrib import messages
        messages.success(request, 'File analysis completed successfully')
        return redirect('sandbox')