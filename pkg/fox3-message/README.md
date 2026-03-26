[![Qodana](https://github.com/Ne0nd0g/merlin-message/actions/workflows/qodana.yml/badge.svg)](https://github.com/Ne0nd0g/merlin-message/actions/workflows/qodana.yml)
[![CodeQL](https://github.com/Ne0nd0g/merlin-message/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ne0nd0g/merlin-message/actions/workflows/codeql.yml)
[![GoReportCard](https://goreportcard.com/badge/github.com/Ne0nd0g/merlin-message)](https://goreportcard.com/report/github.com/Ne0nd0g/merlin-message)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/release/Ne0nd0g/merlin-message.svg)](https://github.com/Ne0nd0g/merlin-message/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Ne0nd0g/merlin-message/total.svg)](https://github.com/Ne0nd0g/merlin-message/releases)
[![Twitter Follow](https://img.shields.io/twitter/follow/merlin_c2.svg?style=social&label=Follow)](https://twitter.com/merlin_c2)

# Merlin Message

Messages and embedded Jobs exchanged between a Merlin Server and a Merlin Agent.

This package was separated out so that it can be updated independently of the Merlin Server and Agent packages.

Gob-encoded messages must come from the same package for the encoding and decoding to work between the Server and Agent.
Merlin Agent traffic can use gob encoding, but it is not required to. Encoding transforms must match how the Merlin 
Server listener is configured.

> The Main Merlin C2 repository can be found here: <https://github.com/Ne0nd0g/merlin>