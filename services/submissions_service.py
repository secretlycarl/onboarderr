"""
Submissions Service for Onboarderr

This service handles form submissions for both Plex and Audiobookshelf,
including loading, saving, and managing submission data.
"""

import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from config import get_config
from utils.data_utils import load_json_file, save_json_file

def debug_log(message: str) -> None:
    """Log a debug message only if FLASK_DEBUG is enabled."""
    try:
        flask_debug = os.getenv("FLASK_DEBUG", "0") == "1"
        if flask_debug:
            print(f"[DEBUG] {message}")
    except Exception:
        pass

class SubmissionsService:
    """Service for handling form submissions."""
    
    def __init__(self):
        """Initialize the submissions service."""
        debug_log("Initializing SubmissionsService")
        self.config = get_config()
        debug_log("SubmissionsService initialized")
    
    def load_plex_submissions(self) -> List[Dict[str, Any]]:
        """
        Load Plex submissions from file.
        
        Returns:
            List of Plex submissions
        """
        debug_log("Loading Plex submissions")
        submissions = load_json_file("plex_submissions.json", [])
        debug_log(f"Loaded {len(submissions)} Plex submissions")
        return submissions
    
    def save_plex_submissions(self, submissions: List[Dict[str, Any]]) -> bool:
        """
        Save Plex submissions to file.
        
        Args:
            submissions: List of submissions to save
            
        Returns:
            True if successful, False otherwise
        """
        debug_log(f"Saving {len(submissions)} Plex submissions")
        result = save_json_file("plex_submissions.json", submissions)
        debug_log(f"Plex submissions save result: {result}")
        return result
    
    def load_audiobookshelf_submissions(self) -> List[Dict[str, Any]]:
        """
        Load Audiobookshelf submissions from file.
        
        Returns:
            List of Audiobookshelf submissions
        """
        debug_log("Loading Audiobookshelf submissions")
        submissions = load_json_file("audiobookshelf_submissions.json", [])
        debug_log(f"Loaded {len(submissions)} Audiobookshelf submissions")
        return submissions
    
    def save_audiobookshelf_submissions(self, submissions: List[Dict[str, Any]]) -> bool:
        """
        Save Audiobookshelf submissions to file.
        
        Args:
            submissions: List of submissions to save
            
        Returns:
            True if successful, False otherwise
        """
        debug_log(f"Saving {len(submissions)} Audiobookshelf submissions")
        result = save_json_file("audiobookshelf_submissions.json", submissions)
        debug_log(f"Audiobookshelf submissions save result: {result}")
        return result
    
    def add_plex_submission(self, email: str, selected_keys: List[str], 
                           selected_titles: List[str], explicit_content: bool = False) -> bool:
        """
        Add a new Plex submission.
        
        Args:
            email: User's email address
            selected_keys: Selected library keys
            selected_titles: Selected library titles
            explicit_content: Whether user accepts explicit content
            
        Returns:
            True if successful, False otherwise
        """
        debug_log(f"Adding Plex submission for {email}")
        
        submission_entry = {
            "email": email,
            "libraries_keys": selected_keys,
            "libraries_titles": selected_titles,
            "explicit_content": explicit_content,
            "submitted_at": datetime.now(timezone.utc).isoformat() + "Z"
        }
        
        submissions = self.load_plex_submissions()
        submissions.append(submission_entry)
        
        result = self.save_plex_submissions(submissions)
        debug_log(f"Plex submission add result: {result}")
        return result
    
    def add_audiobookshelf_submission(self, email: str, username: str, 
                                     password: str, explicit_content: bool = False) -> bool:
        """
        Add a new Audiobookshelf submission.
        
        Args:
            email: User's email address
            username: Requested username
            password: Requested password
            explicit_content: Whether user accepts explicit content
            
        Returns:
            True if successful, False otherwise
        """
        debug_log(f"Adding Audiobookshelf submission for {email}")
        
        submission_entry = {
            "email": email,
            "username": username,
            "password": password,
            "explicit_content": explicit_content,
            "submitted_at": datetime.now(timezone.utc).isoformat() + "Z"
        }
        
        submissions = self.load_audiobookshelf_submissions()
        submissions.append(submission_entry)
        
        result = self.save_audiobookshelf_submissions(submissions)
        debug_log(f"Audiobookshelf submission add result: {result}")
        return result
    
    def check_duplicate_email(self, email: str, submission_type: str = "plex") -> bool:
        """
        Check if an email has already been submitted.
        
        Args:
            email: Email address to check
            submission_type: Type of submission ("plex" or "audiobookshelf")
            
        Returns:
            True if email already exists, False otherwise
        """
        debug_log(f"Checking for duplicate email: {email} ({submission_type})")
        
        if submission_type.lower() == "plex":
            submissions = self.load_plex_submissions()
        elif submission_type.lower() == "audiobookshelf":
            submissions = self.load_audiobookshelf_submissions()
        else:
            debug_log(f"Unknown submission type: {submission_type}")
            return False
        
        existing_emails = [submission.get("email", "").lower() for submission in submissions]
        is_duplicate = email.lower() in existing_emails
        
        debug_log(f"Email {email} is {'duplicate' if is_duplicate else 'new'} for {submission_type}")
        return is_duplicate
    
    def get_submission_stats(self) -> Dict[str, int]:
        """
        Get submission statistics.
        
        Returns:
            Dictionary with submission counts
        """
        debug_log("Getting submission stats")
        
        plex_submissions = self.load_plex_submissions()
        abs_submissions = self.load_audiobookshelf_submissions()
        
        stats = {
            "plex_submissions": len(plex_submissions),
            "audiobookshelf_submissions": len(abs_submissions),
            "total_submissions": len(plex_submissions) + len(abs_submissions)
        }
        
        debug_log(f"Submission stats: {stats}")
        return stats
    
    def delete_submission(self, submission_type: str, index: int) -> bool:
        """
        Delete a submission by index.
        
        Args:
            submission_type: Type of submission ("plex" or "audiobookshelf")
            index: Index of submission to delete
            
        Returns:
            True if successful, False otherwise
        """
        debug_log(f"Deleting {submission_type} submission at index {index}")
        
        if submission_type.lower() == "plex":
            submissions = self.load_plex_submissions()
            if 0 <= index < len(submissions):
                deleted = submissions.pop(index)
                result = self.save_plex_submissions(submissions)
                debug_log(f"Deleted Plex submission: {deleted.get('email', 'unknown')}")
                return result
        elif submission_type.lower() == "audiobookshelf":
            submissions = self.load_audiobookshelf_submissions()
            if 0 <= index < len(submissions):
                deleted = submissions.pop(index)
                result = self.save_audiobookshelf_submissions(submissions)
                debug_log(f"Deleted Audiobookshelf submission: {deleted.get('email', 'unknown')}")
                return result
        
        debug_log(f"Failed to delete {submission_type} submission at index {index}")
        return False 