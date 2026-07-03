import logging

log = logging.getLogger("falconeye.image_search.exif")

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    _HAVE_PIL = True
except ImportError:
    _HAVE_PIL = False
    log.warning("Pillow not installed; EXIF extraction disabled")


def extract_exif(file_path: str) -> dict:
    """Extract EXIF metadata from a JPEG file. Returns empty dict on failure or non-JPEG."""
    if not _HAVE_PIL:
        return {}
    try:
        img = Image.open(file_path)
        if img.format not in ("JPEG", "TIFF"):
            return {}
        exif = img.getexif()
        if not exif:
            return {}

        result: dict = {}
        result["width"] = img.width
        result["height"] = img.height

        tag_map = {v: k for k, v in TAGS.items()}

        def _tag(name):
            return exif.get(tag_map.get(name, 0))

        make = _tag("Make")
        if make:
            result["camera_make"] = str(make).strip()
        model = _tag("Model")
        if model:
            result["camera_model"] = str(model).strip()
        dt = _tag("DateTimeOriginal")
        if dt:
            result["datetime_original"] = str(dt).strip()
        sw = _tag("Software")
        if sw:
            result["software"] = str(sw).strip()
        ori = _tag("Orientation")
        if ori:
            result["orientation"] = int(ori)

        gps_ifd = exif.get_ifd(34853)
        if gps_ifd:
            gps = _parse_gps(gps_ifd)
            if gps:
                result["gps"] = gps

        return result
    except Exception as exc:
        log.debug("EXIF extraction failed for %s: %s", file_path, exc)
        return {}


def _dms_to_decimal(dms, ref: str) -> float:
    d, m, s = float(dms[0]), float(dms[1]), float(dms[2])
    decimal = d + m / 60.0 + s / 3600.0
    if ref in ("S", "W"):
        decimal = -decimal
    return round(decimal, 6)


def _parse_gps(gps_ifd: dict):
    try:
        lat_dms = gps_ifd.get(2)
        lat_ref = gps_ifd.get(1) or "N"
        lon_dms = gps_ifd.get(4)
        lon_ref = gps_ifd.get(3) or "E"
        if not lat_dms or not lon_dms:
            return None
        out = {
            "lat": _dms_to_decimal(lat_dms, str(lat_ref)),
            "lon": _dms_to_decimal(lon_dms, str(lon_ref)),
        }
        alt_raw = gps_ifd.get(6)
        alt_ref = gps_ifd.get(5) or 0
        if alt_raw is not None:
            alt = float(alt_raw)
            if alt_ref == b"\x01" or alt_ref == 1:
                alt = -alt
            out["altitude"] = round(alt, 2)
        return out
    except Exception as exc:
        log.debug("GPS parse failed: %s", exc)
        return None
