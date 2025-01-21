import struct
from Crypto.Cipher import AES
import os
import argparse

# AES解密参数
AES_KEY = b"bajk3b4j3bvuoa3h"
AES_IV = b"mers46ha35ga23hn"

def aes_decrypt(data):
    """使用AES解密"""
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = cipher.decrypt(data)
    # 移除PKCS#7填充
    pad_length = decrypted[-1]
    if pad_length < 1 or pad_length > 16:
        raise ValueError("Invalid padding")
    return decrypted[:-pad_length]

def xor_decrypt(data):
    """对数据前112字节进行XOR解密"""
    return bytes(b ^ 0x66 if i < 112 else b for i, b in enumerate(data))

def extract_dex(file_path):
    """解密加密的DEX文件"""
    with open(file_path, 'rb') as f:
        dex_data = f.read()

    # 获取壳DEX大小（小端格式）
    shell_dex_length = struct.unpack('>I', dex_data[-4:])[0]
    shell_dex = dex_data[:shell_dex_length]
    print(f"Extracted shell dex: {len(shell_dex)} bytes")

    # 提取加密部分
    encrypted_data = dex_data[shell_dex_length:-4]

    # 解析AES加密部分
    encrypted_aes = encrypted_data[:528]  # 前512字节是AES加密
    decrypted_aes = aes_decrypt(encrypted_aes)
    # 拼接AES解密结果和后续数据
    remaining_data = encrypted_data[528:]
    full_decrypted_data = decrypted_aes + remaining_data

    # 解析application名长度和内容
    app_name_length = full_decrypted_data[0]
    app_name = full_decrypted_data[1:1 + app_name_length].decode()
    print(f"Application name: {app_name}")

    # 解析第一个源DEX大小和内容
    offset = 1 + app_name_length
    source_dex1_size = struct.unpack('>I', full_decrypted_data[offset:offset + 4])[0]
    offset += 4
    source_dex1 = full_decrypted_data[offset:offset + source_dex1_size]
    offset += source_dex1_size
    print(f"First source dex size: {len(source_dex1)} bytes")
    # 解析XOR加密部分
    decrypted_dexes = []
    while offset < len(full_decrypted_data):
        # 获取当前DEX的大小
        source_dex_size = struct.unpack('>I', full_decrypted_data[offset:offset + 4])[0]
        offset += 4
        source_dex = full_decrypted_data[offset:offset + source_dex_size]
        offset += source_dex_size

        # 解密前112字节
        decrypted_dex = xor_decrypt(source_dex)
        decrypted_dexes.append(decrypted_dex)
        print(f"Decrypted source dex: {len(decrypted_dex)} bytes")

    return shell_dex, source_dex1, decrypted_dexes

def save_dex_files(shell_dex, first_dex, dex_list, output_dir):
    """保存解密后的DEX文件"""
    import os
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 保存壳DEX
    with open(os.path.join(output_dir, 'shell.dex'), 'wb') as f:
        f.write(shell_dex)

    # 保存第一个源DEX
    with open(os.path.join(output_dir, 'source1.dex'), 'wb') as f:
        f.write(first_dex)

    # 保存其他源DEX
    for i, dex in enumerate(dex_list):
        with open(os.path.join(output_dir, f'source{i + 2}.dex'), 'wb') as f:
            f.write(dex)

if __name__ == "__main__":
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description="Decrypt classes.dex and extract DEX files.")
    parser.add_argument("-f", "--file", required=True, help="Path to the input classes.dex file.")
    parser.add_argument("-o", "--output", required=True, help="Directory to save the extracted DEX files.")
    args = parser.parse_args()

    # 获取输入和输出路径
    input_file = args.file
    output_dir = args.output

    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        exit(1)

    # 创建输出目录（如果不存在）
    os.makedirs(output_dir, exist_ok=True)

    # 解密并提取DEX文件
    try:
        shell_dex, first_dex, other_dexes = extract_dex(input_file)
        save_dex_files(shell_dex, first_dex, other_dexes, output_dir)
        print(f"Decryption completed. Extracted files saved to '{output_dir}'.")
    except Exception as e:
        print(f"Error during decryption: {e}")
        exit(1)
