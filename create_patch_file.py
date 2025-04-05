import argparse
import sys
import filecmp

def compare_files(original_path, modified_path, output_path):
    try:
        # Read both files in binary mode
        with open(original_path, 'rb') as orig_file, open(modified_path, 'rb') as mod_file:
            original_bytes = orig_file.read()
            modified_bytes = mod_file.read()
            
            assert len(original_bytes) == len(modified_bytes)

            if original_bytes == modified_bytes:
                print('Files are identical. No patch file written.')
                return
            
            # Open output file for writing
            with open(output_path, 'w') as out_file:
                # Compare bytes and write differences
                for i in range(len(original_bytes)):
                    orig_byte = original_bytes[i]
                    mod_byte = modified_bytes[i]
                    
                    if orig_byte != mod_byte:
                        # Format: address,original_byte,new_byte
                        address = f"0x{i:08x}"
                        line = f"{address},{hex(orig_byte)},{hex(mod_byte)}\n"
                        out_file.write(line)
                        
        print(f"Patch written to {output_path}")
        
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
    except PermissionError as e:
        print(f"Error: Permission denied - {e}")
    except Exception as e:
        print(f"Error: An unexpected error occurred - {e}")

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='Create patch file in format address,original_byte,new_byte'
    )
    parser.add_argument('original', help='Path to original file')
    parser.add_argument('modified', help='Path to modified file')
    parser.add_argument('output', help='Path to output file')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Run comparison
    compare_files(args.original, args.modified, args.output)

if __name__ == '__main__':
    main()