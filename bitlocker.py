from volatility3.framework import interfaces, renderers, objects, symbols, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins import windows
import binascii
import os

class Bitlocker(interfaces.plugins.PluginInterface):
    """Extract Bitlocker FVEK. Supports Windows 7 - 10."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name='primary', description="Memory layer for the kernel", architectures=["Intel32", "Intel64"]
            ),
            requirements.SymbolTableRequirement(
                name='nt_symbols', description="Windows kernel symbols"
            ),
            requirements.StringRequirement(name='dump_dir', description="Directory to dump FVEK", default=None, optional=True),
            requirements.StringRequirement(name='dislocker_dir', description="Directory to dump FVEK for Dislocker", default=None, optional=True),
            requirements.BooleanRequirement(
                name='verbose', description="Enable verbose output", default=False, optional=True
            ),
            requirements.BooleanRequirement(
                name='debug', description="Enable debug output", default=False, optional=True
            ),
        ]

    def run(self):
        layer_name = self.config['primary']
        symbol_table = self.config['nt_symbols']

        # Create the kernel module if needed
        kernel = self.context.module(symbol_table, layer_name, offset=0)

        is_64bit = symbols.symbol_table_is_64bit(self.context, symbol_table)

        if is_64bit:
            kuser_shared_data_addr = 0xFFFFF78000000000
        else:
            kuser_shared_data_addr = 0xFFDF0000

        kuser_shared_data = self.context.object(
            symbol_table + constants.BANG + "_KUSER_SHARED_DATA",
            layer_name=layer_name,
            offset=kuser_shared_data_addr,
        )

        major_version = int(kuser_shared_data.NtMajorVersion)
        minor_version = int(kuser_shared_data.NtMinorVersion)
        build_number = int(kuser_shared_data.NtBuildNumber & 0xFFFF)

        winver = (major_version, minor_version, build_number)

        PoolSize = {
            'Fvec128': 508,
            'Fvec256': 1008,
            'Cngb128': 632,
            'Cngb256': 672,
            'None128': 1230,
            'None256': 1450,
        }
        BLMode = {
            '00': 'AES 128-bit with Diffuser',
            '01': 'AES 256-bit with Diffuser',
            '02': 'AES 128-bit',
            '03': 'AES 256-bit',
            '10': 'AES 128-bit (Win 8+)',
            '20': 'AES 256-bit (Win 8+)',
            '30': 'AES-XTS 128 bit (Win 10+)',
            '40': 'AES-XTS 256 bit (Win 10+)',
        }

        results = []

        if winver >= (6, 4, 10241):
            mode = "30"
            if self.config.get('verbose', False):
                self._log_info(
                    "Looking for FVEKs inside memory pools used by BitLocker in Windows 10/2016/2019."
                )
            tweak = "Not Applicable"

            constraints = [
                windows.poolscanner.PoolConstraint(
                    tag=b'None',
                    type_name=symbol_table + constants.BANG + '_POOL_HEADER',
                    page_type=windows.poolscanner.PoolType.NONPAGED,
                    size=(PoolSize['None128'], PoolSize['None256']),
                    skip_type_test=True,
                )
            ]

            # Adjust alignment based on architecture
            alignment = 0x10 if is_64bit else 8

            # Use the pool_scan class method directly
            for constraint, header in windows.poolscanner.PoolScanner.pool_scan(
                context=self.context,
                layer_name=layer_name,
                symbol_table=symbol_table,
                pool_constraints=constraints,
                alignment=alignment,
                progress_callback=self._progress_callback
            ):
                pool_offset = header.vol.offset
                pool_size = alignment * header.BlockSize

                # Read the pool data
                data = self.context.layers[layer_name].read(
                    pool_offset, pool_size
                )

                if is_64bit:
                    fvek1OffsetRel = 0x9C
                    fvek2OffsetRel = 0xE0
                    fvek3OffsetRel = 0xC0  # For AES-CBC encryption method
                else:
                    # For 32-bit architectures (update offsets accordingly)
                    fvek1OffsetRel = 0x6C
                    fvek2OffsetRel = 0xB0
                    fvek3OffsetRel = 0x90

                f1 = data[fvek1OffsetRel:fvek1OffsetRel + 64]
                f2 = data[fvek2OffsetRel:fvek2OffsetRel + 64]
                f3 = data[fvek3OffsetRel:fvek3OffsetRel + 64]

                # Extract and validate FVEKs
                if f1[:16] == f2[:16]:
                    if f1[16:32] == f2[16:32]:
                        cipher_mode = '40'
                        fvek_length = 32
                    else:
                        cipher_mode = '30'
                        fvek_length = 16

                    fvek = f1[:fvek_length]
                    dislocker_data = None
                    if self.config.get('dislocker', None):
                        prefix = b'\x04' if cipher_mode == '40' else b'\x05'
                        dislocker_data = prefix + b'\x80' + f1
                    results.append(
                        (pool_offset, BLMode[cipher_mode], tweak, fvek, dislocker_data)
                    )
                elif f1[:16] == f3[:16]:
                    if f1[16:32] == f3[16:32]:
                        cipher_mode = '20'
                        fvek_length = 32
                    else:
                        cipher_mode = '10'
                        fvek_length = 16

                    fvek = f1[:fvek_length]
                    dislocker_data = None
                    if self.config.get('dislocker', None):
                        prefix = b'\x03' if cipher_mode == '20' else b'\x02'
                        dislocker_data = prefix + b'\x80' + f1
                    results.append(
                        (pool_offset, BLMode[cipher_mode], tweak, fvek, dislocker_data)
                    )

                if self.config.get('debug', False):
                    self._log_debug(f"Pool Offset: {hex(pool_offset)}")
                    self._log_debug(f"f1: {binascii.hexlify(f1)}")
                    self._log_debug(f"f2: {binascii.hexlify(f2)}")
                    self._log_debug(f"f3: {binascii.hexlify(f3)}")
        else:
            # Handle other Windows versions accordingly
            self._log_info("Windows version not supported by this plugin.")
            return

        return renderers.TreeGrid(
            [
                ("Address", format_hints.Hex),
                ("Cipher", str),
                ("FVEK", str),
                ("Tweak Key", str),
            ],
            self._generator(results),
        )

    def _generator(self, data):
        for (pool_offset, cipher, tweak, fvek_raw, dislocker_data) in data:
            fvek = binascii.hexlify(fvek_raw).decode('utf-8')
            yield (
                0,
                (
                    format_hints.Hex(pool_offset),
                    cipher,
                    fvek,
                    tweak,
                ),
            )
            # Handle dumping of FVEK files
            if self.config.get('dump_dir', None):
                dump_path = os.path.join(
                    self.config['dump_dir'], f"{pool_offset:#x}.fvek"
                )
                with open(dump_path, "w") as f:
                    f.write(fvek + "\n")
                self._log_info(f"FVEK dumped to file: {dump_path}")

            if dislocker_data and self.config.get('dislocker', None):
                dislocker_path = os.path.join(
                    self.config['dislocker'], f"{pool_offset:#x}-Dislocker.fvek"
                )
                with open(dislocker_path, "wb") as f:
                    f.write(dislocker_data)
                self._log_info(
                    f"FVEK for Dislocker dumped to file: {dislocker_path}"
                )
