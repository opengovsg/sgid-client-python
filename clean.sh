#!/usr/bin/env bash
rm -rf .pytest_cache
rm -rf build
rm -rf dist
rm -rf *.egg-info
rm -rf .eggs
rm -rf .cache
rm -rf .coverage
rm -rf .tox
rm -rf .mypy_cache
rm -rf .pytest_cache
rm -rf **/__pycache__
echo "Complete cleaning..."