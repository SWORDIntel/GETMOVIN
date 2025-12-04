#!/usr/bin/env python3
"""
Example: LLM Agent Client Usage

This demonstrates how to connect to the LLM Agent Server and use it
to generate and execute code remotely.
"""

from modules.llm_client import LLMAgentClient
import json


def main():
    # Connect to server
    client = LLMAgentClient(host='localhost', port=8888)
    
    if not client.connect():
        print("Failed to connect to server")
        return
    
    print("Connected to LLM Agent Server\n")
    
    # Test heartbeat
    print("1. Testing heartbeat...")
    response = client.heartbeat()
    if response:
        print(f"   Server status: {response.get('status', 'unknown')}\n")
    
    # Generate code
    print("2. Generating Python code...")
    spec = {
        'language': 'python',
        'description': 'Print hello world and current directory',
        'requirements': ['Print greeting', 'Show current directory'],
        'imports': ['import os']
    }
    
    response = client.generate_code(spec)
    if response and response.get('success'):
        print(f"   Code generated: {response.get('file_path', 'unknown')}")
        print(f"\n   Generated code:\n{response.get('code', '')}\n")
        
        # Execute the generated code
        print("3. Executing generated code...")
        exec_response = client.execute_code(
            response['file_path'],
            response['language']
        )
        
        if exec_response:
            print(f"   Exit code: {exec_response.get('exit_code', -1)}")
            if exec_response.get('stdout'):
                print(f"   Output:\n{exec_response['stdout']}")
            if exec_response.get('stderr'):
                print(f"   Errors:\n{exec_response['stderr']}")
    
    # Execute a command
    print("\n4. Executing PowerShell command...")
    cmd_response = client.send_command('Get-Date', 'powershell')
    if cmd_response:
        print(f"   Output:\n{cmd_response.get('stdout', '')}")
    
    # Disconnect
    client.disconnect()
    print("\nDisconnected from server")


if __name__ == '__main__':
    main()
