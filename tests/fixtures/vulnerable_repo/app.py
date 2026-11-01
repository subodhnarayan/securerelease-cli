"""Intentionally vulnerable fixture. Never deploy this code."""
import sqlite3
import subprocess

import yaml


def load_config(raw):
    return yaml.load(raw, Loader=yaml.Loader)


def run_user_command(user_input):
    return subprocess.run("ls " + user_input, shell=True)


def find_user(conn: sqlite3.Connection, name):
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()


def calculate(expression):
    return eval(expression)
