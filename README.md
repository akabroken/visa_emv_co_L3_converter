# EMVCo L3 ISO8583 Log Converter

This Python script parses Inovant VTS log files containing ISO8583 message data (e.g., `0100`, `0110`) and converts them into structured **EMVCo Level 3 XML format**.

## Features

- Parses both `0100 Request` and `0110 Response` messages
- Extracts field values (`sDATA`) and optionally `sACDATA`
- Builds XML with `<FieldList>`, `<FieldBinary>`, and `<RawData>`
- Supports special value handling like `{Expected, But Not Received}`

## Usage

1. Place your Inovant VTS log in `log_string` inside `main()`
2. Run the script: `python emvco_parser.py`
3. Output saved as `emvco_output.xml`

## Dependencies

- `lxml`
- `re` (standard library)

## Future Improvements (To Do)

- [ ] Add support for binary field encoding (BMP, TLV parsing)
- [ ] Validate generated XML against EMVCo schema
- [ ] Handle multiple connection IDs and TCPIP parameters
- [ ] Allow input via file path or stdin
- [ ] Improve field type mapping using real EMVCo definitions
- [ ] Add unit tests for field extraction and XML generation
