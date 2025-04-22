# apkanalyzer.py - APK analysis logic
import os
import hashlib
import zipfile
import re
import json
import xml.etree.ElementTree as ET
import requests
import logging
import subprocess
from datetime import datetime

logger = logging.getLogger(__name__)

class APKAnalyzer:
    def __init__(self):
        # Known malware signatures (in production, use a comprehensive database)
        self.malware_signatures = [
            "com.android.bot",
            "com.fake.app",
            "malicious_string_pattern",
            "suspicious_permission_pattern"
        ]
        
        # Known legitimate applications database
        self.known_legitimate_apps = {
            "com.whatsapp": {"name": "WhatsApp", "developer": "Meta"},
            "com.facebook.katana": {"name": "Facebook", "developer": "Meta"},
            "com.instagram.android": {"name": "Instagram", "developer": "Meta"},
            "com.google.android.youtube": {"name": "YouTube", "developer": "Google LLC"},
            "com.spotify.music": {"name": "Spotify", "developer": "Spotify AB"},
            "com.netflix.mediaclient": {"name": "Netflix", "developer": "Netflix, Inc."},
            "com.amazon.mShop.android.shopping": {"name": "Amazon Shopping", "developer": "Amazon Mobile LLC"},
            "com.ubercab": {"name": "Uber", "developer": "Uber Technologies, Inc."},
            "com.twitter.android": {"name": "Twitter", "developer": "Twitter, Inc."},
            "com.snapchat.android": {"name": "Snapchat", "developer": "Snap Inc."},
            # Add more legitimate apps as needed
        }
        
        # Dangerous permissions that could indicate malicious activity
        self.dangerous_permissions = [
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "CAMERA",
            "RECORD_AUDIO",
            "READ_CONTACTS",
            "READ_SMS",
            "SEND_SMS",
            "READ_PHONE_STATE",
            "READ_CALL_LOG",
            "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
            "RECEIVE_BOOT_COMPLETED",
            "SYSTEM_ALERT_WINDOW"
        ]

    def analyze_apk(self, apk_path):
        """Main function to analyze an APK file"""
        logger.info(f"Starting analysis of {apk_path}")
        
        # Calculate file hash
        file_hash = self._calculate_hash(apk_path)
        logger.info(f"File hash: {file_hash}")
        
        # Extract basic APK information
        apk_info = self._extract_apk_info(apk_path)
        logger.info(f"Extracted APK info: {json.dumps(apk_info, indent=2)}")
        
        # Check with VirusTotal (simulated in this example)
        vt_result = self._check_virus_total(file_hash)
        
        # Analyze permissions
        permission_analysis = self._check_permissions(apk_info.get('permissions', []))
        
        # Check if app is potentially a clone
        clone_check = self._check_clone_app(apk_info.get('package_name', ''))
        
        # Check for code obfuscation
        code_obfuscation = self._check_code_obfuscation(apk_path)
        
        # Check for known malware patterns
        malware_patterns = self._check_malware_patterns(apk_path, apk_info)
        
        # Check for network security
        network_security = self._check_network_security(apk_path)
        
        # Calculate overall safety score
        vt_score = 100 - (vt_result['positives'] / vt_result['total'] * 100)
        permission_score = 100 - permission_analysis['risk_score']
        clone_score = 0 if clone_check['is_potential_clone'] else 100
        obfuscation_score = 100 - (code_obfuscation['obfuscation_level'] * 25)  # Higher obfuscation -> lower score
        
        # Weight factors for overall score
        weights = {
            'vt_score': 0.4,
            'permission_score': 0.3,
            'clone_score': 0.2,
            'obfuscation_score': 0.1
        }
        
        overall_safety = (
            vt_score * weights['vt_score'] + 
            permission_score * weights['permission_score'] + 
            clone_score * weights['clone_score'] + 
            obfuscation_score * weights['obfuscation_score']
        )
        
        # Adjust score based on malware patterns
        if malware_patterns['malware_detected']:
            overall_safety *= 0.5  # Cut score in half if malware patterns found
        
        # Determine security assessment
        security_assessment = "Safe"
        if overall_safety < 50:
            security_assessment = "Dangerous"
        elif overall_safety < 75:
            security_assessment = "Suspicious"
        
        # Compile final result
        analysis_result = {
            'timestamp': datetime.now().isoformat(),
            'file_hash': file_hash,
            'package_name': apk_info.get('package_name'),
            'app_name': apk_info.get('app_name'),
            'version': apk_info.get('version'),
            'permissions': apk_info.get('permissions', []),
            'activities': apk_info.get('activities', []),
            'virus_scan': vt_result,
            'permission_analysis': permission_analysis,
            'clone_analysis': clone_check,
            'code_obfuscation': code_obfuscation,
            'malware_patterns': malware_patterns,
            'network_security': network_security,
            'scores': {
                'virus_total': vt_score,
                'permissions': permission_score,
                'clone': clone_score,
                'obfuscation': obfuscation_score
            },
            'overall_safety_score': overall_safety,
            'assessment': security_assessment,
            'recommendations': self._generate_recommendations(
                permission_analysis, 
                clone_check, 
                code_obfuscation,
                security_assessment
            )
        }
        
        logger.info(f"Analysis complete for {apk_path}")
        return analysis_result

    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash of the file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _extract_apk_info(self, apk_path):
        """Extract comprehensive information from the APK file"""
        info = {
            "permissions": [],
            "activities": [],
            "package_name": None,
            "app_name": None,
            "version": None,
            "min_sdk": None,
            "target_sdk": None,
            "libraries": [],
            "services": []
        }
        
        try:
            # In a real implementation, use a library like androguard
            # This is simplified for demonstration purposes
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                # Process the manifest file
                if 'AndroidManifest.xml' in zip_ref.namelist():
                    manifest = zip_ref.read('AndroidManifest.xml')
                    
                    # Extract package name (simplified - use proper XML parsing in production)
                    package_match = re.search(b'package="([^"]+)"', manifest)
                    if package_match:
                        info['package_name'] = package_match.group(1).decode('utf-8')
                    
                    # Extract version info (simplified)
                    version_match = re.search(b'versionName="([^"]+)"', manifest)
                    if version_match:
                        info['version'] = version_match.group(1).decode('utf-8')
                    
                    # Extract permissions (simplified)
                    for permission in re.findall(b'android.permission.([A-Z_]+)', manifest):
                        info['permissions'].append(permission.decode('utf-8'))
                    
                    # Extract activities (simplified)
                    for activity in re.findall(b'<activity[^>]*android:name="([^"]+)"', manifest):
                        info['activities'].append(activity.decode('utf-8'))
                
                # Try to extract app name from resources
                resource_files = [f for f in zip_ref.namelist() if f.startswith('res/values/') and f.endswith('.xml')]
                for res_file in resource_files:
                    try:
                        xml_content = zip_ref.read(res_file)
                        if b'app_name' in xml_content:
                            # Simplified - would need proper XML parsing
                            app_name_match = re.search(b'<string name="app_name">([^<]+)</string>', xml_content)
                            if app_name_match:
                                info['app_name'] = app_name_match.group(1).decode('utf-8')
                                break
                    except:
                        continue
        
        except Exception as e:
            logger.error(f"Error extracting APK info: {str(e)}", exc_info=True)
            info['error'] = str(e)
        
        return info

    def _check_virus_total(self, file_hash):
        """
        Check file hash with VirusTotal API.
        In a production system, you would use your API key.
        """
        logger.info(f"Checking VirusTotal for hash: {file_hash}")
        
        # Simulated API call - in production use actual API with rate limiting
        # response = requests.get(
        #     f'https://www.virustotal.com/vtapi/v2/file/report',
        #     params={'apikey': 'YOUR_API_KEY', 'resource': file_hash}
        # )
        
        # For demo purposes, return simulated result
        # In production, analyze the actual API response
        return {
            "positives": 0,  # Number of engines detecting it as malicious
            "total": 70,     # Total number of scanning engines
            "scan_date": datetime.now().isoformat(),
            "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
        }

    def _check_permissions(self, permissions):
        """Analyze permissions for suspicious patterns"""
        found_dangerous = [p for p in permissions if p in self.dangerous_permissions]
        
        # Calculate risk score based on number and type of dangerous permissions
        permission_count = len(permissions)
        dangerous_count = len(found_dangerous)
        
        # Different permissions have different weights
        high_risk_permissions = ["READ_SMS", "SEND_SMS", "READ_CONTACTS", "READ_PHONE_STATE"]
        high_risk_count = len([p for p in found_dangerous if p in high_risk_permissions])
        
        # Calculate weighted risk score
        if permission_count == 0:
            risk_score = 0
        else:
            base_score = (dangerous_count / len(self.dangerous_permissions)) * 70
            high_risk_bonus = (high_risk_count / max(1, len(high_risk_permissions))) * 30
            risk_score = base_score + high_risk_bonus
        
        return {
            "total_permissions": permission_count,
            "dangerous_count": dangerous_count,
            "dangerous_permissions": found_dangerous,
            "high_risk_permissions": [p for p in found_dangerous if p in high_risk_permissions],
            "risk_score": min(risk_score, 100)  # Cap at 100%
        }

    def _check_clone_app(self, package_name):
        """Check if the app might be a clone of a legitimate app"""
        if not package_name:
            return {"is_potential_clone": False, "clone_details": None}
        
        result = {"is_potential_clone": False, "clone_details": None}
        
        # Check if package name is similar to known apps
        for known_pkg, details in self.known_legitimate_apps.items():
            # Exact match - not a clone but might need developer verification
            if package_name == known_pkg:
                return {
                    "is_potential_clone": False,
                    "matched_legitimate_app": details
                }
            
            # Check for similarity using various methods
            
            # 1. Simple substring check
            if known_pkg in package_name or package_name in known_pkg:
                # 2. Calculate Jaccard similarity for more precision
                similarity = self._calculate_similarity(package_name, known_pkg)
                
                if similarity > 0.7:  # Arbitrary threshold
                    result = {
                        "is_potential_clone": True,
                        "similarity_score": similarity,
                        "original_app": details,
                        "original_package": known_pkg
                    }
                    break
        
        return result

    def _calculate_similarity(self, str1, str2):
        """Calculate Jaccard similarity between two strings"""
        set1 = set(str1)
        set2 = set(str2)
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        return intersection / union if union > 0 else 0

    def _check_code_obfuscation(self, apk_path):
        """Check for signs of code obfuscation"""
        obfuscation_indicators = 0
        max_indicators = 4
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                # Check for small method names (a, b, c, etc.)
                dex_files = [f for f in zip_ref.namelist() if f.endswith('.dex')]
                
                # Check if app has proguard mapping file
                has_proguard = any('proguard' in f for f in zip_ref.namelist())
                if has_proguard:
                    obfuscation_indicators += 1
                
                # Look for single-letter class or method names in dex
                for dex_file in dex_files:
                    # This is simplified. In reality, you'd need to parse the DEX file properly
                    dex_content = zip_ref.read(dex_file)
                    
                    # Check for single-letter class names pattern (simplified)
                    if re.search(b'L[a-z]/[a-z];', dex_content):
                        obfuscation_indicators += 1
                    
                    # Check for simple array of single character method names
                    if re.search(b'[a-z]\x00[a-z]\x00[a-z]\x00[a-z]\x00[a-z]', dex_content):
                        obfuscation_indicators += 1
                
                # Check for encrypted strings or resources
                if any('assets/encrypted' in f for f in zip_ref.namelist()):
                    obfuscation_indicators += 1
        
        except Exception as e:
            logger.error(f"Error checking obfuscation: {str(e)}", exc_info=True)
        
        # Calculate obfuscation level from 0-4
        obfuscation_level = min(obfuscation_indicators, max_indicators)
        
        return {
            "obfuscation_level": obfuscation_level,
            "max_level": max_indicators,
            "is_heavily_obfuscated": obfuscation_level >= 3,
            "indicators": obfuscation_indicators
        }

    def _check_malware_patterns(self, apk_path, apk_info):
        """Check for known malware patterns in the APK"""
        malware_detected = False
        detection_reasons = []
        
        try:
            # Check package name against known malicious patterns
            package_name = apk_info.get('package_name', '')
            for signature in self.malware_signatures:
                if signature in package_name:
                    malware_detected = True
                    detection_reasons.append(f"Package name matches known malware pattern: {signature}")
            
            # Check for suspicious permission combinations
            permissions = set(apk_info.get('permissions', []))
            suspicious_combinations = [
                {"perms": {"READ_SMS", "SEND_SMS", "RECEIVE_SMS"}, "reason": "SMS interception capability"},
                {"perms": {"READ_CONTACTS", "INTERNET", "READ_SMS"}, "reason": "Contact data exfiltration capability"},
                {"perms": {"RECEIVE_BOOT_COMPLETED", "DISABLE_KEYGUARD"}, "reason": "System interference capability"}
            ]
            
            for combo in suspicious_combinations:
                if combo["perms"].issubset(permissions):
                    malware_detected = True
                    detection_reasons.append(f"Suspicious permission combination: {combo['reason']}")
            
            # Check file content for known malicious patterns
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    # Skip common resource files
                    if file_info.filename.startswith('res/') or file_info.filename.endswith('.png'):
                        continue
                    
                    # Check code and config files
                    if file_info.filename.endswith('.dex') or file_info.filename.endswith('.xml'):
                        content = zip_ref.read(file_info.filename)
                        
                        # Check for suspicious URL patterns (C&C servers, etc.)
                        suspicious_domains = ['evil.com', 'malware.server', 'data-steal.net', 'command-control.org']
                        for domain in suspicious_domains:
                            if domain.encode() in content:
                                malware_detected = True
                                detection_reasons.append(f"Suspicious domain reference found: {domain}")
                        
                        # Check for suspicious code patterns
                        suspicious_code = [
                            b'getDeviceId', 
                            b'getSubscriberId',
                            b'getSimSerialNumber',
                            b'executeCommand'
                        ]
                        for pattern in suspicious_code:
                            if pattern in content:
                                # This is a rough check, would need more context in real app
                                if not any(good_pattern in detection_reasons for good_pattern in ["game", "utility"]):
                                    detection_reasons.append(f"Suspicious code pattern found: {pattern.decode()}")
        
        except Exception as e:
            logger.error(f"Error checking malware patterns: {str(e)}", exc_info=True)
            detection_reasons.append(f"Error during malware check: {str(e)}")
        
        return {
            "malware_detected": malware_detected,
            "detection_reasons": detection_reasons
        }

    def _check_network_security(self, apk_path):
        """Check network security configuration"""
        result = {
            "uses_cleartext_traffic": False,
            "has_network_security_config": False,
            "has_certificate_pinning": False,
            "risk_level": "low"
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                # Check AndroidManifest for network security settings
                if 'AndroidManifest.xml' in zip_ref.namelist():
                    manifest = zip_ref.read('AndroidManifest.xml')
                    
                    # Check if app allows cleartext traffic
                    if b'android:usesCleartextTraffic="true"' in manifest:
                        result["uses_cleartext_traffic"] = True
                        result["risk_level"] = "medium"
                    
                    # Check for network security config
                    if b'android:networkSecurityConfig' in manifest:
                        result["has_network_security_config"] = True
                
                # Look for network security config file
                security_configs = [f for f in zip_ref.namelist() if 'network_security_config.xml' in f]
                
                for config_file in security_configs:
                    config_content = zip_ref.read(config_file)
                    
                    # Check for certificate pinning
                    if b'<pin ' in config_content or b'<pin-set>' in config_content:
                        result["has_certificate_pinning"] = True
                        result["risk_level"] = "low"  # Good security practice
                    
                    # Check if cleartext traffic is allowed in config
                    if b'cleartextTrafficPermitted="true"' in config_content:
                        result["uses_cleartext_traffic"] = True
                        result["risk_level"] = "medium"
        
        except Exception as e:
            logger.error(f"Error checking network security: {str(e)}", exc_info=True)
        
        return result

    def _generate_recommendations(self, permission_analysis, clone_check, code_obfuscation, security_assessment):
        """Generate user recommendations based on analysis"""
        recommendations = []
        
        # Base recommendation based on overall assessment
        if security_assessment == "Dangerous":
            recommendations.append("Do not install this application as it shows strong signs of being malicious.")
        elif security_assessment == "Suspicious":
            recommendations.append("Exercise caution with this application as it shows some suspicious characteristics.")
        
        # Permission-based recommendations
        if permission_analysis["dangerous_count"] > 3:
            recommendations.append(f"This app requests {permission_analysis['dangerous_count']} potentially dangerous permissions, which is higher than average.")
        
        if permission_analysis["risk_score"] > 70:
            recommendations.append("The combination of permissions requested by this app could potentially compromise your privacy.")
        
        # Clone analysis recommendations
        if clone_check["is_potential_clone"]:
            original_app = clone_check.get("original_app", {}).get("name", "a legitimate app")
            recommendations.append(f"This appears to be a clone of {original_app}. Consider downloading from the official source instead.")
        
        # Obfuscation recommendations
        if code_obfuscation["is_heavily_obfuscated"]:
            recommendations.append("This app uses heavy code obfuscation, which can sometimes indicate an attempt to hide malicious functionality.")
        
        # If all looks good
        if not recommendations:
            recommendations.append("This app appears to be safe based on our analysis.")
        
        return recommendations