from contextlib import contextmanager
import os
import shutil
import tempfile


def _parse_base_address(value):
    if value is None:
        return None
    try:
        text = str(value).strip()
        if text.lower().startswith('0x'):
            return int(text, 16)
        return int(text, 10)
    except Exception:
        return None


def _apply_loader_option(loader, method_name, value):
    if not hasattr(loader, method_name):
        return loader
    try:
        result = getattr(loader, method_name)(value)
        return result if result is not None else loader
    except Exception:
        return loader


@contextmanager
def load_program(binary_path, analyze=True):
    import pyghidra
    from java.io import File

    project_dir = tempfile.mkdtemp(prefix='arael_')
    project_name = 'AraelProject'

    try:
        with pyghidra.open_project(project_dir, project_name, create=True) as project:
            binary_file = File(str(binary_path))
            loader = pyghidra.program_loader().source(binary_file).project(project)

            language_id = os.environ.get('ARAEL_GHIDRA_LANGUAGE')
            if language_id:
                try:
                    from ghidra.program.model.lang import LanguageID
                    language_id = LanguageID(language_id)
                except Exception:
                    pass
                loader = _apply_loader_option(loader, 'language', language_id)
                loader = _apply_loader_option(loader, 'set_language', language_id)

            with loader.load() as load_results:
                loaded = load_results.getPrimary()
                if loaded is None:
                    raise RuntimeError('Failed to load binary')
                program = loaded.getDomainObject()
                image_base = _parse_base_address(os.environ.get('ARAEL_IMAGE_BASE'))
                if image_base is not None:
                    try:
                        addr_space = program.getAddressFactory().getDefaultAddressSpace()
                        base_addr = addr_space.getAddress(image_base)
                        if program.getImageBase().getOffset() != image_base:
                            program.setImageBase(base_addr, True)
                    except Exception:
                        pass
                if analyze:
                    pyghidra.analyze(program)
                yield program
    finally:
        shutil.rmtree(project_dir, ignore_errors=True)


def format_address(address):
    if address is None:
        return None
    try:
        offset = address.getOffset()
    except AttributeError:
        try:
            offset = int(str(address), 16)
        except Exception:
            return str(address)
    return f'0x{offset:x}'
