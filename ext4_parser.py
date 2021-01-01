import sys
import struct
import datetime

def sum_high_low(h, l):
    return (h << 32) + l

def sum_high_low16(h, l):
    return (h << 16) + l

class PrintValuesClass(dict):
    def __str__(self):
        attrs = []
        for k in self.keys():
            attrs.append('{}: {}'.format(k, self[k]))
        return '\n'.join(attrs)

class SuperBlock(PrintValuesClass):
    '''base ext4'''
    super_block_size = 1024
    _SUPER_BLOCK_ATTRIBUTES_NAME = [
        # ref: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
        "inodes_count",
        "blocks_count_lo",
        "r_blocks_count_lo",
        "free_blocks_count_lo",
        "free_inodes_count",
        "first_data_block",
        "block_size",
        "cluster_size",
        "blocks_per_group",
        "clusters_per_group",
        "inodes_per_group",
        "mount_time",
        "write_time",
        "mount_count",
        "max_mount_count",
        "magic",
        "state",
        "errors",
        "minor_rev_level",
        "lastcheck",
        "checkinterval",
        "creator_os",
        "rev_level",
        "default_resuid",
        "default_resgid",
        "first_ino",
        "inode_size",
        "block_group_nr",
        "feature_compat",
        "feature_incompat",
        "feature_ro_compat",
        "uuid",
        "volume_name",
        "last_mounted",
        "algorithm_usage_bitmap",
        "prealloc_blocks",
        "prealloc_dir_blocks",
        "reserved_gdt_blocks",
        "journal_uuid",
        "journal_inum",
        "journal_dev",
        "last_orphan",
        "hash_seed",
        "def_hash_version",
        "jnl_backup_type",
        "desc_size",
        "default_mount_opts",
        "first_meta_bg",
        "mkfs_time",
        "jnl_blocks",
        "blocks_count_hi",
        "r_blocks_count_hi",
        "free_blocks_count_hi",
        "min_extra_isize",
        "want_extra_isize",
        "flags",
        "raid_stride",
        "mmp_interval",
        "mmp_block",
        "raid_stripe_width",
        "groups_per_flex",
        "checksum_type",
        "reserved_pad",
        "kbytes_written",
        "snapshot_inum",
        "snapshot_id",
        "snapshot_r_blocks_count",
        "snapshot_list",
        "error_count",
        "first_error_time",
        "first_error_ino",
        "first_error_block",
        "first_error_func",
        "first_error_line",
        "last_error_time",
        "last_error_ino",
        "last_error_line",
        "last_error_block",
        "last_error_func",
        "mount_opts",
        "usr_quota_inum",
        "grp_quota_inum",
        "overhead_blocks",
        "backup_bgs",
        "encrypt_algos",
        "encrypt_pw_salt",
        "lpf_ino",
        "prj_quota_inum",
        "checksum_seed",
        "checksum"
    ]

    def __init__(self, raw: bytes):
        super().__init__(
            zip(
                self._SUPER_BLOCK_ATTRIBUTES_NAME, 
                struct.unpack('< iiiiiiiiiiiiihh2shhhiiiihhihhiii16s16s64sibbh16siii16sbbhiii68siiihhihhqibbhqiiqiiiiq32siiiiq32s64siii8si16siii392xi', raw)
            )
        )
        
        self['block_size'] = 1024 << self['block_size']
        self['cluster_size'] = 1024 << self['cluster_size']
        self['groups_per_flex'] = 2 ** self['groups_per_flex']

        self['mount_time'] = datetime.datetime.fromtimestamp(self['mount_time'])
        self['write_time'] = datetime.datetime.fromtimestamp(self['write_time'])
        self['lastcheck'] = datetime.datetime.fromtimestamp(self['lastcheck'])
        self['mkfs_time'] = datetime.datetime.fromtimestamp(self['mkfs_time'])
        
        self['creator_os'] = ['Linux', 'Hurd', 'Masix', 'FreeBSD', 'Lites'][self['creator_os']]

        self['magic'] = self['magic'].hex(' ').upper()
        self['uuid'] = self['uuid'].hex(' ').upper()
        self['journal_uuid'] = self['journal_uuid'].hex(' ').upper()
        self['hash_seed'] = self['hash_seed'].hex(' ').upper()
        self['jnl_blocks'] = self['jnl_blocks'].hex(' ').upper()
        self['backup_bgs'] = self['backup_bgs'].hex(' ').upper()
        self['encrypt_pw_salt'] = self['encrypt_pw_salt'].hex(' ').upper()

        self['volume_name'] = self['volume_name'][ : self['volume_name'].find(b'\x00')].decode()
        self['last_mounted'] = self['last_mounted'][ : self['last_mounted'].find(b'\x00')].decode()
        self['first_error_func'] = self['first_error_func'][ : self['first_error_func'].find(b'\x00')].decode()
        self['last_error_func'] = self['last_error_func'][ : self['last_error_func'].find(b'\x00')].decode()
        self['mount_opts'] = self['mount_opts'][ : self['mount_opts'].find(b'\x00')].decode()

        self['blocks_count'] = sum_high_low(self['blocks_count_hi'], self['blocks_count_lo'])
        self['r_blocks_count'] = sum_high_low(self['r_blocks_count_hi'], self['r_blocks_count_lo'])
        self['free_blocks_count'] = sum_high_low(self['free_blocks_count_hi'], self['free_blocks_count_lo'])



class GDT(PrintValuesClass):
    '''base ext4'''
    gdt_size = 64
    _GDT_ATTRIBUTES_NAME = [
        # ref: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
        "block_bitmap_lo",
        "inode_bitmap_lo",
        "inode_table_lo",
        "free_blocks_count_lo",
        "free_inodes_count_lo",
        "used_dirs_count_lo",
        "flags",
        "exclude_bitmap_lo",
        "block_bitmap_csum_lo",
        "inode_bitmap_csum_lo",
        "itable_unused_lo",
        "checksum",
        "block_bitmap_hi",
        "inode_bitmap_hi",
        "inode_table_hi",
        "free_blocks_count_hi",
        "free_inodes_count_hi",
        "used_dirs_count_hi",
        "itable_unused_hi",
        "exclude_bitmap_hi",
        "block_bitmap_csum_hi",
        "inode_bitmap_csum_hi"
    ]

    def __init__(self, raw: bytes):
        super().__init__(
            zip(
                self._GDT_ATTRIBUTES_NAME,
                struct.unpack('< iiiHhhhihhhhiiihhhhihh4x', raw)
            )
        )

        self['block_bitmap'] = sum_high_low(self['block_bitmap_hi'], self['block_bitmap_lo'])
        self['inode_bitmap'] = sum_high_low(self['inode_bitmap_hi'], self['inode_bitmap_lo'])
        self['inode_table'] = sum_high_low(self['inode_table_hi'], self['inode_table_lo'])
        self['free_blocks_count'] = sum_high_low(self['free_blocks_count_hi'], self['free_blocks_count_lo'])
        self['free_inodes_count'] = sum_high_low(self['free_inodes_count_hi'], self['free_inodes_count_lo'])
        self['used_dirs_count'] = sum_high_low(self['used_dirs_count_hi'], self['used_dirs_count_lo'])
        self['exclude_bitmap'] = sum_high_low(self['exclude_bitmap_hi'], self['exclude_bitmap_lo'])
        self['block_bitmap_csum'] = sum_high_low(self['block_bitmap_csum_hi'], self['block_bitmap_csum_lo'])
        self['inode_bitmap_csum'] = sum_high_low(self['inode_bitmap_csum_hi'], self['inode_bitmap_csum_lo'])
        self['itable_unused'] = sum_high_low(self['itable_unused_hi'], self['itable_unused_lo'])



class Inode(PrintValuesClass):
    '''base ext4'''
    _inode_size = 160 # 0xA0
    _INODE_ATTRIBUTES_NAME = [
        # ref: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
        "mode",
        "uid_lo",
        "size_lo",
        "access_time",
        "change_time",
        "modify_time",
        "delete_time",
        "gid_lo",
        "links_count",
        "blocks_lo",
        "flags",
        "version_lo",
        "block",
        "generation",
        "file_acl_lo",
        "size_high",
        "obso_faddr",
        "blocks_high",
        "file_acl_high",
        "uid_high",
        "gid_high",
        "checksum_lo",
        "extra_size",
        "checksum_hi",
        "change_time_extra",
        "modify_time_extra",
        "access_time_extra",
        "create_time",
        "create_time_extra",
        "version_hi",
        "project_id"
    ]

    file_mode_list = {
        0x1000: "(FIFO)",
        0x2000: "(Character device)",
        0x4000: "(Directory)",
        0x6000: "(Block device)",
        0x8000: "(Regular file)",
        0xA000: "(Symbolic link)",
        0xC000: "(Socket)"
    }

    def __init__(self, raw: bytes):
        super().__init__(
            zip(
                self._INODE_ATTRIBUTES_NAME,
                struct.unpack('< Hhiiiiihhiii60siiiihhhhh2xhhiiiiiii', raw[ : self._inode_size])
            )
        )
        self['file_mode'] = self.parse_mode(self['mode'])

        self['access_time'] = datetime.datetime.fromtimestamp(self['access_time'])
        self['change_time'] = datetime.datetime.fromtimestamp(self['change_time'])
        self['modify_time'] = datetime.datetime.fromtimestamp(self['modify_time'])
        self['delete_time'] = datetime.datetime.fromtimestamp(self['delete_time'])
        self['create_time'] = datetime.datetime.fromtimestamp(self['create_time'])

        self['block'] = self['block'].hex(' ').upper()

        self['uid'] = sum_high_low16(self['uid_high'], self['uid_lo'])
        self['gid'] = sum_high_low16(self['gid_high'], self['gid_lo'])
        self['size'] = sum_high_low(self['size_high'], self['size_lo'])
        self['blocks'] = sum_high_low(self['blocks_high'], self['blocks_lo'])
        self['file_acl'] = sum_high_low(self['file_acl_high'], self['file_acl_lo'])
        self['checksum'] = sum_high_low16(self['checksum_hi'], self['checksum_lo'])
        self['version'] = sum_high_low16(self['version_hi'], self['version_lo'])

    def parse_mode(self, mode):
        file_mode = 'None'
        if mode > 0:
            file_mode = oct(mode)[-4:] # ex) 0644
            for m in self.file_mode_list.keys():
                if mode & m:
                    file_mode += self.file_mode_list[m]
                    break
            
        return file_mode
    
    def is_dir(self):
        return (self['mode'] & 0x4000) != 0
    
    def is_file(self):
        return (self['mode'] & 0x8000) != 0



class ExtentHeader(PrintValuesClass):
    extent_header_size = 12

    _EXTENT_HDR_ATTRIBUTES_NAME = [
        # ref: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
        "magic",
        "entries",
        "max",
        "depth",
        "generation"
    ]

    def __init__(self, raw: bytes):
        super().__init__(
            zip(
                self._EXTENT_HDR_ATTRIBUTES_NAME,
                struct.unpack('< 2shhhi', raw)
            )
        )

        self['magic'] = self['magic'].hex(' ').upper()
    
    def is_valid(self):
        return self['magic'] == '0A F3'
    
    def is_leaf(self):
        return self['depth'] == 0
    
    def is_index(self):
        return self['depth'] != 0



class ExtentIndex(PrintValuesClass):
    extent_index_size = 12

    _EXTENT_INDEX_ATTRIBUTES_NAME = [
        # ref: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
        "block",
        "leaf_lo",
        "leaf_hi"
    ]

    def __init__(self, raw: bytes):
        super().__init__(
            zip(
                self._EXTENT_INDEX_ATTRIBUTES_NAME,
                struct.unpack('< iih2x', raw)
            )
        )

        self['leaf'] = sum_high_low16(self['leaf_hi'], self['leaf_lo'])



class ExtentLeaf(PrintValuesClass):
    extent_leaf_size = 12

    _EXTENT_LEAF_ATTRIBUTES_NAME = [
        # ref: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
        "block",
        "len",
        "start_hi",
        "start_lo"
    ]

    def __init__(self, raw: bytes):
        super().__init__(
            zip(
                self._EXTENT_LEAF_ATTRIBUTES_NAME,
                struct.unpack('< ihhi', raw)
            )
        )
        
        self['start'] = sum_high_low16(self['start_hi'], self['start_lo'])

        

class DirEntry(PrintValuesClass):
    _DIR_ENTRY_ATTRIBUTES_NAME = [
        # ref: https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout
        "inode",
        "record_length",
        "name_length",
        "file_type"
    ]

    file_type_list = [
        "Unknown",
        "Regular file",
        "Directory",
        "Character device",
        "Block device",
        "FIFO",
        "Unix socket",
        "Symbolic link"
    ]

    def __init__(self, raw: bytes):
        super().__init__(
            zip(
                self._DIR_ENTRY_ATTRIBUTES_NAME,
                struct.unpack('< ihbb', raw[:8])
            )
        )

        self['name'] = raw[8 : 8 + self['name_length']].decode()
        self['file_type'] = self.file_type_list[self['file_type']]
        
        
        


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: {} <ext4 raw file>'.format(sys.argv[0]))
        exit(0)
    
    ext4_raw_file = sys.argv[1]
    with open(ext4_raw_file, 'rb') as f:
        f.seek(1024)
        
        super_block_raw = f.read(1024)
        super_block = SuperBlock(super_block_raw)
        print('---SUPER BLOCK----------------------------------')
        print(super_block)
        print()

        gdt_offset = super_block['block_size'] if super_block['block_size'] > 1024 else 2048
        print('GDT offset:', gdt_offset, '|', hex(gdt_offset))
        total_group_count = super_block['blocks_count'] // super_block['blocks_per_group']
        print('Total Block Group count:', total_group_count)
        
        bg_size = super_block['block_size'] * super_block['blocks_per_group']
        print('Each Block Group Sector(512) count:', bg_size // 512, '|', hex(bg_size // 512))
        byte_unit = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
        loop_cnt = 0
        while bg_size > 1024:
            bg_size /= 1024
            loop_cnt += 1
        print('Each Block Group size:', bg_size, byte_unit[loop_cnt])
        print()

        f.seek(gdt_offset, 0) # 0: start of file
        gdt_raw = f.read(total_group_count * GDT.gdt_size)
        for i in range(0, len(gdt_raw), GDT.gdt_size):
            gdt = GDT(gdt_raw[i : i + GDT.gdt_size])
            print('---GDT {}----------------------------------'.format(i // GDT.gdt_size))
            print(gdt)
            print()

            print('Exist inode count:', super_block['inodes_per_group'] - gdt['free_inodes_count'])
            print('Block count in use:', super_block['blocks_per_group'] - gdt['free_blocks_count'])
            inode_table_offset = gdt['inode_table'] * super_block['block_size']
            print('Inode table offset:', inode_table_offset , '|', hex(inode_table_offset))
            print()

            inode_table_offset = sum_high_low(gdt['inode_table_hi'], gdt['inode_table_lo']) * super_block['block_size']
            f.seek(inode_table_offset, 0)

            inode_count_in_group = super_block['inodes_per_group'] - sum_high_low(gdt['free_inodes_count_hi'], gdt['free_inodes_count_lo']) + 1
            inode_raw = f.read(inode_count_in_group * super_block['inode_size'])
            for j in range(0, len(inode_raw), super_block['inode_size']):
                inode = Inode(inode_raw[ j : j + super_block['inode_size']])
                print('---INODE {}----------------------------------'.format(j // super_block['inode_size']))
                print(inode)
                print()

                block = bytes.fromhex(inode['block'])
                eh = ExtentHeader(block[ : ExtentHeader.extent_header_size])
                if not eh.is_valid():
                    continue
                print('---Extent Header----------------------------------')
                print(eh)
                print()

                if not eh.is_leaf():
                    continue
                block = block[ExtentHeader.extent_header_size :]
                el = ExtentLeaf(block[ : ExtentLeaf.extent_leaf_size])
                print('---Extent Leaf----------------------------------')
                print(el)
                print()

                if not inode.is_dir():
                    continue
                dir_entry_offset = el['start'] * super_block['block_size']
                f.seek(dir_entry_offset, 0)
                dir_entry_raw = f.read(4084)

                k = 0
                while dir_entry_raw:
                    dir_entry = DirEntry(dir_entry_raw)
                    print('---Directory Entry {}----------------------------------'.format(k))
                    print(dir_entry)
                    print()
                    
                    dir_entry_raw = dir_entry_raw[dir_entry['record_length'] : ]
                    k += 1
