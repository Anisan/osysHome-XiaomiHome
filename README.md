# XiaomiHome - Xiaomi Zigbee Gateway Integration

![XiaomiHome Icon](static/XiaomiHome.png)

Integration with Xiaomi Zigbee Gateway for managing Xiaomi Zigbee devices via multicast UDP protocol.

## Description

The `XiaomiHome` module provides integration with Xiaomi Zigbee Gateway for the osysHome platform. It enables discovery, control, and monitoring of Xiaomi Zigbee devices through multicast UDP communication.

## Main Features

- ✅ **Multicast UDP**: Multicast UDP protocol communication
- ✅ **Device Discovery**: Automatic device discovery
- ✅ **Device Control**: Control Zigbee devices
- ✅ **Command Management**: Manage device commands
- ✅ **Property Linking**: Link device commands to object properties
- ✅ **Method Linking**: Link device commands to object methods
- ✅ **Search Integration**: Search devices and commands

## Admin Panel

The module provides an admin interface for:
- Viewing Xiaomi Zigbee devices
- Configuring device settings
- Managing device commands
- Linking commands to properties

## Configuration

- **Gateway Key**: Xiaomi gateway encryption key
- **Multicast Address**: 224.0.0.50 (default)
- **Multicast Port**: 9898 (default)

## Usage

### Adding Device

1. Navigate to XiaomiHome module
2. Devices discovered automatically via multicast
3. Configure gateway key
4. Link device commands to object properties

## Technical Details

- **Protocol**: Multicast UDP
- **Gateway**: Xiaomi Zigbee Gateway
- **Device Types**: All Zigbee devices supported by Xiaomi gateway
- **Encryption**: Gateway key-based encryption

## Version

Current version: **0.1**

## Category

Devices

## Actions

The module provides the following actions:
- `cycle` - Background device monitoring
- `search` - Search devices and commands

## Requirements

- Flask
- SQLAlchemy
- Socket support
- osysHome core system

## Author

osysHome Team

## License

See the main osysHome project license

