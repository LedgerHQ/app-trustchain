# Trustchain nano application

This application is based on the [application boilerplate](https://github.com/LedgerHQ/app-boilerplate). Checkout out the boilerplate repository to understand how to build and test the application.

## Commands

### Overview
| Command name | INS | Description |
| --- | --- | --- |
| `GET_VERSION` | 0x03 | Get application version as `MAJOR`, `MINOR`, `PATCH` |
| `GET_APP_NAME` | 0x04 | Get ASCII encoded application name |
| `INIT` | 0x06 | Initialize the signature flow, this must be called before any parsing or signature commands |
| `PARSE_STREAM` | 0x08 | Parse a stream to give some context to the signer, this command can be skipped if the block to sign is the first block of a root stream (Seed command) |
| `SIGN_BLOCK` | 0x07 | Parses and sign a new block |
| `SET_TRUSTED_MEMBER` | 0x09 | Sets the current trusted member to the device. |

### GET_VERSION

#### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x03 | 0x00 | 0x00 | 0x00 | - |

#### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| 3 | 0x9000 | `MAJOR (1)` \|\| `MINOR (1)` \|\| `PATCH (1)` |

### GET_APP_NAME

#### Command

| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x04 | 0x00 | 0x00 | 0x00 | - |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `APPNAME (var)` |

### INIT
Initializes the secure flow of the application. This command must be called before calling PARSE_STREAM, SIGN_BLOCK, SET_TRUSTED_MEMBER commands. It expects an ephemeral public key (using SEC1's compressed form: (0x02 or 0x03) || ser256(x)).

The ephemeral public key is used to encrypt data between the device and the client. The device also creates an ephemeral public key which will be released to the client at the end of the signature once the application received user approbation.

#### Command
| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x06 | 0x00 | 0x00 | 0x21 | `EPHEMERAL PUBLIC KEY (SEC1 compressed form)` |

### Response

| Response length (bytes) | SW | RData |
| --- | --- | --- |
| 2 | 0x9000 | - |

### PARSE_STREAM
Parse a stream of signed command blocks. Blocks mmust be split in 3 parts (header, commands, signature) and passed to the device in order. Each command is passed individually to the device (in order). <br>
This command verifies the integrity of the stream and will reset the signature flow if the client attempt to pass an invalid or incomplete stream. <br>

*Note: The application requires streams to always start by a block with a Seed command. If you command stream doesn't with a Seed command, you must prepend the root block of your stream tree to the command stream you want to parse.* 

**Calling this command without having called INIT will result with an error**

**Any error during a call to this command will reset the signer and require the client to call INIT to initialize a new signer**

#### Command
| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x08 | 0x00 Parse block header <br> 0x01 Parse single command <br> 0x02 Parse block signature <br> 0x03 Empty stream | 0x00 | var | `payload` |

#### Response
| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `TRUSTED PROPERTIES` |

### SIGN_BLOCK
Signs a command block. The command block must be first split in 2 parts:
- The block header
- The commands
Each command must then be send to the device separately.

**Calling this command without having called INIT will result with an error**

**Any error or user disapproval during a call to this command will reset the signer and require the client to call INIT to initialize a new signer**        
#### Command
| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x07 | 0x00 Digest block header <br> 0x01 Digest a single command <br> 0x02 Digest the last command and output the signature | 0x00 | var | `payload` |

#### Response
| Response length (bytes) | SW | RData |
| --- | --- | --- |
| var | 0x9000 | `TRUSTED PROPERTIES` |

### SET_TRUSTED_MEMBER
Set the trusted member to use to verify block informations. The trusted member must have been created during the current signer session.

**Note: This command will fail if the device is not currently in a signing session.**

#### Command
| CLA | INS | P1 | P2 | Lc | CData |
| --- | --- | --- | --- | --- | --- |
| 0xE0 | 0x09 | 0x00 Digest block header <br> 0x01 Digest a single command <br> 0x02 Digest the last command and output the signature | 0x00 | var | 0x00 \|\| 0x10 \|\| `IV` \|\|0x06 \|\| `trusted_member_length` \|\| `trusted_member` |

#### Response
| Response length (bytes) | SW | RData |
| --- | --- | --- |
| 2 | 0x9000 | - |

## Status Words

| SW | SW name | Description |
| --- | --- | --- |
| 0x6985 | `SW_DENY` | Rejected by user |
| 0x6A86 | `SW_WRONG_P1P2` | Either `P1` or `P2` is incorrect |
| 0x6A87 | `SW_WRONG_DATA_LENGTH` | `Lc` or minimum APDU length is incorrect |
| 0x6D00 | `SW_INS_NOT_SUPPORTED` | No command exists with `INS` |
| 0x6E00 | `SW_CLA_NOT_SUPPORTED` | Bad `CLA` used for this application |
| 0xB000 | `SW_WRONG_RESPONSE_LENGTH` | Wrong response length (buffer size problem) |
| 0xB007 | `SW_BAD_STATE` | Security issue with bad state |
| 0xB008 | `SW_SIGNATURE_FAIL` | Signature of raw transaction failed |
| 0xB009 | `SW_STREAM_PARSER_BAD_STATE` | Security issue lead by an invalid Command stream |
| 0xB00A | `SW_STREAM_PARSER_INVALID_FORMAT` | Invalid or unsupported command stream format |
| 0xB00B | `SW_TP_BUFFER_OVERFLOW` | Trusted properties buffer can't receive all data |
| 0xB00C | `SW_STREAM_CLOSED` | Attempt to perform an action on a closed stream |
| 0x9000 | `OK` | Success |
