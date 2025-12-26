from contextlib import contextmanager
import shutil
import tempfile


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

            with loader.load() as load_results:
                loaded = load_results.getPrimary()
                if loaded is None:
                    raise RuntimeError('Failed to load binary')
                program = loaded.getDomainObject()
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
