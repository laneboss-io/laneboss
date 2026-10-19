"""Owned process for the Linux controller component test, not a service."""
import sys

sys.stdout.write("ready\n")
sys.stdout.flush()
sys.stdin.buffer.read()
