[![CodeQL](https://github.com/nzyuko/fox3/actions/workflows/codeql.yml/badge.svg)](https://github.com/nzyuko/fox3/actions/workflows/codeql.yml)
[![GoReportCard](https://goreportcard.com/badge/github.com/nzyuko/fox3)](https://goreportcard.com/report/github.com/nzyuko/fox3)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/release/nzyuko/fox3.svg)](https://github.com/nzyuko/fox3/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/nzyuko/fox3/total.svg)](https://github.com/nzyuko/fox3/releases)
[![Twitter Follow](https://img.shields.io/twitter/follow/fox3_c2.svg?style=social&label=Follow)](https://twitter.com/fox3_c2)

# Fox3

<p align="center">
  <img alt="Fox3 Logo" src="docs/images/fox3.png" height="30%" width="30%">
</p>

Fox3 is a cross-platform post-exploitation Command & Control server and agent written in Go.

Highlighted features:

- [fox3-cli](https://github.com/nzyuko/fox3-cli) command line interface over gRPC to connect to the Fox3 Server facilitating multi-user support
- Supported Agent C2 Protocols: http/1.1 clear-text, http/1.1 over TLS, HTTP/2, HTTP/2 clear-text (h2c), http/3 (http/2 over QUIC)
- Peer-to-peer (P2P) communication between Agents with bind or reverse for SMB, TCP, and UDP
- Configurable agent data encoding and encryption transforms: AES, Base64, gob, hex, JWE, RC4, and XOR
    - JWE transform use [PBES2_HS512_A256KW](https://tools.ietf.org/html/rfc7518#section-4.8) PBES2 (RFC 2898) with HMAC
  SHA-512 as the PRF and AES Key Wrap (RFC 3394) using 256-bit keys for the encryption scheme 
- Configurable agent authenticators:
  - None: No authentication 
  - [OPAQUE](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00): Asymmetric Password Authenticated Key Exchange (PAKE)
- Encrypted JWT for message authentication
- Configurable Agent message data [padding](https://fox3-c2.readthedocs.io/en/latest/agent/cli.html#padding) 
  to combat beaconing detections based on a fixed message size
- Execute .NET assemblies in-process with `invoke-assembly` or in a sacrificial process with `execute-assembly`
- Execute arbitrary Windows executables (PE) in a sacrificial process with `execute-pe` 
- Various shellcode execution techniques: CreateThread, CreateRemoteThread, RtlCreateUserThread, QueueUserAPC
- Integrated [Donut](https://github.com/Binject/go-donut), [sRDI](https://github.com/monoxgas/sRDI), 
  and [SharpGen](https://github.com/cobbr/SharpGen) support
- Dynamically change the Agent's [JA3](https://fox3-c2.readthedocs.io/en/latest/agent/cli.html#ja3) hash 
- [Mythic](#mythic) support
- [Documentation & Wiki](https://fox3-c2.readthedocs.io/en/latest/)

An introductory blog post can be found here: <https://medium.com/@Ne0nd0g/introducing-fox3-645da3c635a>

Supporting Repositories:
- [Fox3 Agent](https://github.com/nzyuko/fox3-agent) - Agent source code
- [Fox3 Agent DLL](https://github.com/nzyuko/fox3-agent-dll) - Agent DLL source code
- [Fox3 CLI](https://github.com/nzyuko/fox3-cli) - Command line interface for Fox3
- [Fox3 Documentation](https://github.com/nzyuko/fox3-documentation) - Documentation source code
- [Fox3 on Mythic](https://github.com/MythicAgents/fox3) - Fox3 agent for Mythic Framework
- [Fox3 Docker](https://github.com/nzyuko/fox3-docker) - Base Docker image for for Fox3 images
- [Fox3 Message](https://github.com/nzyuko/fox3-message) - A Go library for Fox3 messages exchanged between a Fox3 Server and Agent

## Quick Start

1. Download the latest version of Fox3 Server from the [releases](https://github.com/nzyuko/fox3/releases) section
   > The Server package contains compiled versions of the CLI and Agent for all the major operating systems in the `data/bin` directory
2. Extract the files with 7zip using the `x` function **The password is: `fox3`**
3. Start Fox3
4. Start the CLI
5. Configure a [listener](https://fox3-c2.readthedocs.io/en/latest/cli/menu/listeners.html)   
6. Deploy an agent. See [Agent Execution Quick Start Guide](https://fox3-c2.readthedocs.io/en/latest/quickStart/quickstart.html#fox3-agent) for examples
7. Pwn, Pivot, Profit

   ```
   mkdir /opt/fox3;cd /opt/fox3
   wget https://github.com/nzyuko/fox3/releases/latest/download/fox3Server-Linux-x64.7z
   7z x fox3Server-Linux-x64.7z
   sudo ./fox3Server-Linux-x64
   ./data/bin/fox3CLI-Linux-x64
   ```

## Mythic

Fox3 can be integrated and used as an agent with the [Mythic](https://github.com/its-a-feature/Mythic) a 
collaborative, multi-platform, red teaming framework.

Visit the [Fox3 on Mythic](https://github.com/MythicAgents/fox3) repository in the MythicAgents organization
to get started.

## Misc.

* To compile Fox3 from source, view the [Custom Build](https://fox3-c2.readthedocs.io/en/latest/quickStart/quickstart.html#fox3-server) page
* For a full list of available commands:
   * [Main Menu](https://fox3-c2.readthedocs.io/en/latest/cli/menu/main.html)
   * [Listener Menu](https://fox3-c2.readthedocs.io/en/latest/cli/menu/listeners.html)
   * [Agent Menu](https://fox3-c2.readthedocs.io/en/latest/cli/menu/agents.html)
   * [Module Menu](https://fox3-c2.readthedocs.io/en/latest/cli/menu/modules.html)
* View the [Frequently Asked Questions](https://fox3-c2.readthedocs.io/en/latest/faq/faq.html) page
* View the [Blog Posts](https://fox3-c2.readthedocs.io/en/latest/misc/blogs.html) page for additional information

## Slack

Join the `#fox3` channel in the [BloodHoundGang](https://bloodhoundgang.herokuapp.com/) Slack to ask questions, 
troubleshoot, or provide feedback.

## JetBrains

Thanks to [JetBrains](https://www.jetbrains.com/?from=fox3) for kindly sponsoring Fox3 by providing a Goland IDE 
Open Source license

<p align="center">
  <img alt="JetBrains Logo" src="docs/images/jetbrains-variant-4.png" height="40%" width="40%">
  <img alt="GoLand Logo" src="docs/images/icon-goland.png" height="20%" width="20%">
</p>
 