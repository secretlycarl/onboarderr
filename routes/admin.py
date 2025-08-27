"""
Admin Routes Module

Handles admin and system functionality that was previously in old_app.py.
This module manages system operations, error logs, and administrative tasks.
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from services.template_context_service import TemplateContextService
from services.library_service import LibraryService
from services.submissions_service import SubmissionsService
from config import get_config
import os

def register_admin_routes(app):
    """Register admin routes with the Flask app."""
    
    # Create blueprint for admin routes
    admin_bp = Blueprint('admin', __name__)
    
    # Initialize services
    template_context_service = TemplateContextService()
    library_service = LibraryService()
    submissions_service = SubmissionsService()
    
    @admin_bp.route("/trigger_restart", methods=["POST"])
    def trigger_restart():
        """Trigger application restart."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return jsonify({"error": "Unauthorized"}), 401
        
        try:
            # Start restart in background thread
            def restart_container_delayed():
                """Restart container after a delay"""
                import time
                import subprocess
                import sys
                
                time.sleep(2)  # Small delay
                try:
                    # Try to restart the application
                    if os.path.exists('compose.yml'):
                        # Docker compose restart
                        subprocess.run(['docker-compose', 'restart'], check=True)
                    else:
                        # Simple process restart
                        os.execv(sys.executable, ['python'] + sys.argv)
                except Exception as e:
                    print(f"Restart failed: {e}")
            
            # Start restart thread
            import threading
            restart_thread = threading.Thread(target=restart_container_delayed, daemon=True)
            restart_thread.start()
            
            return jsonify({"status": "restarting"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @admin_bp.route("/check-restart-readiness", methods=["GET"])
    def check_restart_readiness():
        """Check if the system is ready for restart."""
        
        try:
            # Get poster service for status checks
            from services.poster_service import PosterService
            poster_service = PosterService()
            
            # Check if we should wait for posters
            should_wait = poster_service.should_wait_for_posters()
            ready = not should_wait  # Ready if we don't need to wait for posters
            
            # Get poster status
            poster_status = {
                "in_progress": poster_service.is_download_in_progress(),
                "worker_running": poster_service.download_running,
                "queue_size": len(poster_service.download_queue),
                "progress": poster_service.get_download_progress()
            }
            
            # Get setup download status
            setup_download_status = {}
            current_phase = "idle"
            
            unified_status = poster_service.get_unified_status()
            if unified_status:
                setup_download_status['unified'] = unified_status
                
                # Determine current phase based on unified status
                status = unified_status.get('status', 'idle')
                if status == 'checking':
                    current_phase = "checking"
                elif status == 'no_downloads_needed':
                    current_phase = "no_downloads_needed"
                elif status == 'server_offline':
                    current_phase = "server_offline"
                elif status == 'plex_downloading':
                    current_phase = "plex"
                elif status == 'plex_completed':
                    current_phase = "plex_completed"
                elif status == 'abs_downloading':
                    current_phase = "abs"
                elif status == 'completed':
                    current_phase = "completed"
                elif status == 'error':
                    current_phase = "error"
            
            # Get ABS-specific status
            abs_enabled = poster_service.config.get("ABS_ENABLED", "yes") == "yes"
            abs_needs_refresh = poster_service.should_refresh_abs_posters() if abs_enabled else False
            abs_download_in_progress = poster_service.is_abs_download_in_progress()
            abs_download_completed = poster_service.is_abs_download_completed()
            
            return jsonify({
                "ready": ready,
                "poster_status": poster_status,
                "setup_download_status": setup_download_status,
                "current_phase": current_phase,
                "should_wait_for_posters": should_wait,
                "abs_enabled": abs_enabled,
                "abs_needs_refresh": abs_needs_refresh,
                "abs_download_in_progress": abs_download_in_progress,
                "abs_download_completed": abs_download_completed
            })
            
        except Exception as e:
            return jsonify({"ready": True, "error": str(e)})
    
    @admin_bp.route("/error-logs", methods=["GET", "POST"])
    def error_logs():
        """Handle error logs page."""
        
        # Check if user is authenticated
        if not session.get("admin_authenticated", False):
            return redirect(url_for("login"))
        
        try:
            # Get template context
            context = template_context_service.get_template_context()
            
            # Add error logs specific context
            context.update({
                'page_title': 'Error Logs - Onboarderr',
                'current_page': 'error_logs'
            })
            
            # This will be implemented with actual error log loading logic
            context['error_logs'] = []
            
            return render_template("error_logs.html", **context)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Register the blueprint with the app
    app.register_blueprint(admin_bp) 