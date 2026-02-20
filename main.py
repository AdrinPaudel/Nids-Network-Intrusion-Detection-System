#!/usr/bin/env python
"""
Main Entry Point for NIDS Backend
This serves as the central orchestrator for starting the backend and frontend
Currently acts as a placeholder for future integration with frontend services
"""

import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

import argparse
from ml_model.utils import log_message, print_section_header


def main():
    """Main entry point - will coordinate backend and frontend services"""
    parser = argparse.ArgumentParser(
        description='NIDS Backend - Main Entry Point',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE:
  # Start full pipeline
  python main.py --pipeline
  
  # Start backend services only
  python main.py --backend
  
  # Import from ml_model or classification modules for specific tasks
        """
    )
    
    parser.add_argument(
        '--pipeline',
        action='store_true',
        help='Run the complete ML pipeline'
    )
    
    parser.add_argument(
        '--backend',
        action='store_true',
        help='Start backend services'
    )
    
    args = parser.parse_args()
    
    if not args.pipeline and not args.backend:
        parser.print_help()
        return
    
    if args.pipeline:
        print_section_header("NIDS ML Pipeline")
        log_message("For ML pipeline, use: python ml_model.py --help", level="INFO")
        log_message("Or: python main.py (when integrated with ml_model)", level="INFO")
    
    if args.backend:
        print_section_header("NIDS Backend Services")
        log_message("Backend services placeholder", level="INFO")
        log_message("For classification/prediction, use: python classification.py --help", level="INFO")


if __name__ == '__main__':
    main()
