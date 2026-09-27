"""A module that fails at import time, used to test entry-point import failures."""

raise RuntimeError("this module cannot be imported")
