from revanity_gpu.backends.cuda import CudaBackend
from revanity_gpu.backends.cuda_native import CudaNativeBackend
from revanity_gpu.backends.opencl import OpenCLBackend
from revanity_gpu.config import MatchMode
from revanity_gpu.patterns import CompiledPattern


def test_backend_interfaces_smoke():
    patterns = [CompiledPattern.compile(MatchMode.PREFIX, "dead")]
    hashes = [bytes.fromhex("dead" + "0" * 28), bytes.fromhex("beef" + "0" * 28)]

    cuda = CudaBackend()
    cres = cuda.find_matches(hashes, patterns) if cuda.available() else None
    if cres:
        assert cres.backend_name == "cuda"

    cuda_native = CudaNativeBackend()
    nres = cuda_native.find_matches(hashes, patterns) if cuda_native.available() else None
    if nres:
        assert nres.backend_name == "cuda-native"

    opencl = OpenCLBackend()
    ores = opencl.find_matches(hashes, patterns) if opencl.available() else None
    if ores:
        assert ores.backend_name == "opencl"
