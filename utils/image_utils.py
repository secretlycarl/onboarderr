"""
Image utilities for Onboarderr application.

This module provides image processing functions for logo, wordmark, and favicon handling.
"""

import os
from typing import Optional
from PIL import Image
from utils.validation_utils import validate_file_extension


def process_uploaded_logo(file) -> bool:
    """
    Process uploaded logo file and create favicon.
    
    Args:
        file: Uploaded file object
        
    Returns:
        bool: True if processing successful, False otherwise
    """
    if not file or file.filename == '':
        return False
    
    # Check file extension
    allowed_extensions = {'.png', '.webp', '.jpg', '.jpeg'}
    if not validate_file_extension(file.filename, allowed_extensions):
        return False
    
    try:
        # Open image with PIL
        img = Image.open(file.stream)
        
        # Handle different image modes properly
        img = _normalize_image_mode(img)
        
        # Save logo based on original format
        file_ext = os.path.splitext(file.filename)[1].lower()
        logo_path = os.path.join('static', 'clearlogo.webp')
        
        if file_ext in ['.png', '.webp']:
            # For PNG and WebP, preserve original format and transparency
            if file_ext == '.png':
                logo_path = os.path.join('static', 'clearlogo.png')
                _save_image_with_transparency(img, logo_path, 'PNG')
            else:  # .webp
                _save_image_with_transparency(img, logo_path, 'WEBP')
        else:
            # For JPG/JPEG, convert to WebP (no transparency support)
            _save_jpeg_to_webp(img, logo_path)
        
        # Create favicon (32x32) - preserve transparency if available
        favicon = img.resize((32, 32), Image.Resampling.LANCZOS)
        favicon_path = os.path.join('static', 'favicon.webp')
        _save_image_with_transparency(favicon, favicon_path, 'WEBP')
        
        return True
    except Exception as e:
        from utils.logging_utils import log_error
        log_error("image_processing", f"Error processing logo: {e}", {"filename": file.filename}, e)
        return False


def process_uploaded_wordmark(file) -> bool:
    """
    Process uploaded wordmark file.
    
    Args:
        file: Uploaded file object
        
    Returns:
        bool: True if processing successful, False otherwise
    """
    if not file or file.filename == '':
        return False
    
    # Check file extension
    allowed_extensions = {'.png', '.webp', '.jpg', '.jpeg'}
    if not validate_file_extension(file.filename, allowed_extensions):
        return False
    
    try:
        # Open image with PIL
        img = Image.open(file.stream)
        
        # Handle different image modes properly
        img = _normalize_image_mode(img)
        
        # Save wordmark based on original format
        file_ext = os.path.splitext(file.filename)[1].lower()
        wordmark_path = os.path.join('static', 'wordmark.webp')
        
        if file_ext in ['.png', '.webp']:
            # For PNG and WebP, preserve original format and transparency
            if file_ext == '.png':
                wordmark_path = os.path.join('static', 'wordmark.png')
                _save_image_with_transparency(img, wordmark_path, 'PNG')
            else:  # .webp
                _save_image_with_transparency(img, wordmark_path, 'WEBP')
        else:
            # For JPG/JPEG, convert to WebP (no transparency support)
            _save_jpeg_to_webp(img, wordmark_path)
        
        return True
    except Exception as e:
        from utils.logging_utils import log_error
        log_error("image_processing", f"Error processing wordmark: {e}", {"filename": file.filename}, e)
        return False


def get_logo_filename() -> str:
    """
    Get the current logo filename (could be PNG or WebP).
    
    Returns:
        str: Logo filename
    """
    if os.path.exists(os.path.join('static', 'clearlogo.png')):
        return 'clearlogo.png'
    elif os.path.exists(os.path.join('static', 'clearlogo.webp')):
        return 'clearlogo.webp'
    else:
        return 'clearlogo.webp'  # default fallback


def get_wordmark_filename() -> str:
    """
    Get the current wordmark filename (could be PNG or WebP).
    
    Returns:
        str: Wordmark filename
    """
    if os.path.exists(os.path.join('static', 'wordmark.png')):
        return 'wordmark.png'
    elif os.path.exists(os.path.join('static', 'wordmark.webp')):
        return 'wordmark.webp'
    else:
        return 'wordmark.webp'  # default fallback


def resize_image(image: Image.Image, size: tuple, maintain_aspect: bool = True) -> Image.Image:
    """
    Resize image while optionally maintaining aspect ratio.
    
    Args:
        image: PIL Image object
        size: Target size as (width, height)
        maintain_aspect: Whether to maintain aspect ratio
        
    Returns:
        Image.Image: Resized image
    """
    if maintain_aspect:
        # Calculate aspect ratio
        img_ratio = image.width / image.height
        target_ratio = size[0] / size[1]
        
        if img_ratio > target_ratio:
            # Image is wider than target
            new_width = size[0]
            new_height = int(size[0] / img_ratio)
        else:
            # Image is taller than target
            new_height = size[1]
            new_width = int(size[1] * img_ratio)
        
        resized = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Create new image with target size and paste resized image
        result = Image.new(image.mode, size, (255, 255, 255, 0) if image.mode == 'RGBA' else (255, 255, 255))
        paste_x = (size[0] - new_width) // 2
        paste_y = (size[1] - new_height) // 2
        result.paste(resized, (paste_x, paste_y))
        
        return result
    else:
        return image.resize(size, Image.Resampling.LANCZOS)


def convert_image_format(image: Image.Image, format: str, quality: int = 95) -> Image.Image:
    """
    Convert image to specified format.
    
    Args:
        image: PIL Image object
        format: Target format ('PNG', 'WEBP', 'JPEG')
        quality: Quality for lossy formats (1-100)
        
    Returns:
        Image.Image: Converted image
    """
    if format.upper() == 'JPEG':
        # Convert to RGB for JPEG
        if image.mode == 'RGBA':
            # Create white background
            rgb_image = Image.new('RGB', image.size, (255, 255, 255))
            rgb_image.paste(image, mask=image.split()[-1])  # Use alpha channel as mask
            return rgb_image
        elif image.mode != 'RGB':
            return image.convert('RGB')
        else:
            return image
    elif format.upper() == 'WEBP':
        # WebP supports RGBA
        if image.mode not in ['RGB', 'RGBA']:
            return image.convert('RGBA')
        else:
            return image
    elif format.upper() == 'PNG':
        # PNG supports RGBA
        if image.mode not in ['RGB', 'RGBA']:
            return image.convert('RGBA')
        else:
            return image
    else:
        return image


def _normalize_image_mode(img: Image.Image) -> Image.Image:
    """
    Normalize image mode for consistent processing.
    
    Args:
        img: PIL Image object
        
    Returns:
        Image.Image: Normalized image
    """
    if img.mode == 'P':
        # Convert palette images to RGBA to preserve transparency
        return img.convert('RGBA')
    elif img.mode == 'LA':
        # Convert grayscale with alpha to RGBA
        return img.convert('RGBA')
    elif img.mode == 'L':
        # Convert grayscale to RGB (no transparency)
        return img.convert('RGB')
    elif img.mode in ['RGB', 'RGBA']:
        # These modes are fine as-is
        return img
    else:
        # Convert any other modes to RGB
        return img.convert('RGB')


def _save_image_with_transparency(img: Image.Image, path: str, format: str):
    """
    Save image with transparency support.
    
    Args:
        img: PIL Image object
        path: Output file path
        format: Image format
    """
    if format.upper() == 'PNG':
        img.save(path, 'PNG')
    elif format.upper() == 'WEBP':
        if img.mode == 'RGBA':
            img.save(path, 'WEBP', lossless=True)
        else:
            img.save(path, 'WEBP', quality=95)
    else:
        img.save(path, format)


def _save_jpeg_to_webp(img: Image.Image, path: str):
    """
    Save JPEG image converted to WebP.
    
    Args:
        img: PIL Image object
        path: Output file path
    """
    if img.mode == 'RGBA':
        # Convert RGBA to RGB for JPEG compatibility
        rgb_img = Image.new('RGB', img.size, (255, 255, 255))
        rgb_img.paste(img, mask=img.split()[-1])  # Use alpha channel as mask
        rgb_img.save(path, 'WEBP', quality=95)
    else:
        img.save(path, 'WEBP', quality=95)


def create_thumbnail(image: Image.Image, size: tuple = (150, 150)) -> Image.Image:
    """
    Create a thumbnail of the image.
    
    Args:
        image: PIL Image object
        size: Thumbnail size as (width, height)
        
    Returns:
        Image.Image: Thumbnail image
    """
    return resize_image(image, size, maintain_aspect=True)


def get_image_info(image_path: str) -> Optional[dict]:
    """
    Get basic information about an image file.
    
    Args:
        image_path: Path to image file
        
    Returns:
        Optional[dict]: Image information or None if error
    """
    try:
        with Image.open(image_path) as img:
            return {
                'format': img.format,
                'mode': img.mode,
                'size': img.size,
                'width': img.width,
                'height': img.height,
                'filename': os.path.basename(image_path)
            }
    except Exception as e:
        from utils.logging_utils import log_error
        log_error("image_info", f"Error getting image info: {e}", {"path": image_path}, e)
        return None


def validate_image_file(file_path: str) -> bool:
    """
    Validate that a file is a valid image.
    
    Args:
        file_path: Path to image file
        
    Returns:
        bool: True if valid image, False otherwise
    """
    try:
        with Image.open(file_path) as img:
            img.verify()
        return True
    except Exception:
        return False 