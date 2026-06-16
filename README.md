# LLM-based Security Log Analysis Assistant

## Overview
A prototype security analysis assistant that uses LLMs to analyze logs, identify suspicious patterns, and provide explanations for security analysts.

## Motivation
Security analysts often need to review large volumes of logs.
This project explored whether LLMs can assist log review.

## Demo

![LLM Red Team Scanner Demo](assets/scanner_demo.png)

## Features

- Security log input and analysis interface
- LLM-based suspicious behavior analysis
- Attack pattern explanation
- Security report generation

## Architecture

```text
Security Logs
      |
      v
Log Analysis Interface
      |
      v
Gemini API
      |
      v
LLM-based Security Analysis
      |
      +--> Threat Classification
      |
      +--> Risk Assessment
      |
      +--> Explanation Report

## Tech Stack

- Python
- Gemini API
- Streamlit
- OWASP LLM Top 10

## My Role

- Implemented LLM-based analysis workflow
- Integrated Gemini API
- Designed security analysis prompts
- Built prototype interface

## Limitation

This project was developed as a hackathon prototype.

The goal was to explore LLM-assisted security analysis workflows, not to build a production-level security scanner.

## Future Work

- Integration with real security logs
- Improving detection accuracy with security datasets
- Cloud-based log monitoring integration
