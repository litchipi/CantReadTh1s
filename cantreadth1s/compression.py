import lz4
import bz2
import zlib
import lzma

class CompressionWrapper:
    COMPRESSION_ALGORITHMS_AVAILABLE = ["lzma", "bz2", "zlib", "lz4", "none"]
    DEFAULT_COMPRESSION_ALGORITHM = "zlib"

    def __init__(self, ncpu, algo_n):
        self.compressor, self.decompressor = self.init_cmp_dcp(algo_n)

    def init_cmp_dcp(self, cnb):
        ctype = self.COMPRESSION_ALGORITHMS_AVAILABLE[cnb]
        if (ctype == "lzma"):
            return lzma.LZMACompressor(), lzma.LZMADecompressor()
        elif (ctype == "bz2"):
            return bz2.BZ2Compressor(), bz2.BZ2Decompressor()
        elif (ctype == "zlib"):
            return zlib.compressobj(level=9), zlib.decompressobj()
        elif (ctype == "lz4"):
            return LZ4Wrapper(True), LZ4Wrapper(False)
        elif (ctype == "none"):
            return None, None
        else:
            raise Exception("Compression algorithm not found")

    def compress(self, data):
        if self.compressor is None:
            return data
        else:
            return self.compressor.compress(data)

    def decompress(self, data):
        if self.decompressor is None:
            return data
        else:
            return self.decompressor.decompress(data)# + self.decompressor.flush()

    def cmp_finish(self):
        if self.decompressor is None:
            return "".encode()
        return self.compressor.flush()



class LZ4Wrapper:
    def __init__(self, compress):
        self.beginned = False
        if compress:
            #self.obj = lz4.stream.LZ4StreamCompressor(strat, buffsize)
            self.obj = lz4.frame.LZ4FrameCompressor()
        else:
            #self.obj = lz4.stream.LZ4StreamDecompressor(strat, buffsize)
            self.obj = lz4.frame.LZ4FrameDecompressor()
    def compress(self, data):
        if not self.beginned:
            self.beginned = True
            return self.obj.begin() + self.obj.compress(data)
        return self.obj.compress(data)
    def decompress(self, data):
        return self.obj.decompress(data)
    def flush(self):
        return self.obj.flush()


