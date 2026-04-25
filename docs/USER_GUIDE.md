# XiaomiHome - User Guide

![XiaomiHome Icon](../static/XiaomiHome.png "XiaomiHome plugin")

## Purpose

`XiaomiHome` integrates Xiaomi Zigbee Gateway devices into osysHome using multicast UDP (`224.0.0.50:9898`).

The module is designed to:

- discover Xiaomi gateway/sub-devices from incoming multicast traffic;
- keep a local registry of devices and parsed parameters;
- map Xiaomi parameters to `Object.property` and `Object.method`;
- send control commands back to Xiaomi devices when osysHome properties change.

> [!IMPORTANT]
> Integration is bidirectional: Xiaomi -> osysHome (telemetry/events) and osysHome -> Xiaomi (control writes).

---

## What the User Gets

| Capability | What it does |
| --- | --- |
| Auto discovery | Creates devices automatically from gateway traffic (`sid`, `model`, token, IP) |
| Command registry | Creates/updates command records (`xicommands`) from incoming data |
| Property linking | Writes values to linked osysHome properties |
| Method linking | Calls linked osysHome methods on events |
| Reverse control | Converts osysHome property updates into Xiaomi `write` packets |
| Search support | Returns linked commands in global search (`search` action) |

---

## Interface Overview

Admin page:

```text
/admin/XiaomiHome
```

Main actions from UI:

1. Open device editor (`?op=edit&device=<id>`)
2. Delete device (`?op=delete&device=<id>`)
3. Edit command links (object/property/method)
4. Save updated links and gateway key

### Device table columns

| Column | Meaning |
| --- | --- |
| Title | Friendly device name |
| Type | Xiaomi model (`gateway`, `plug`, `sensor_ht`, `magnet`, ...) |
| SID | Xiaomi `sid` |
| IP | Gateway IP used for control packets |
| Updated | Last update timestamp from incoming traffic |

---

## Quick Start Checklist

- [ ] Open `/admin/XiaomiHome`.
- [ ] Wait for multicast discovery traffic (the plugin sends `{"cmd":"whois"}` on start).
- [ ] Open discovered gateway device and set `Key` (`gate_key`).
- [ ] Open each device and map required commands to osysHome object properties/methods.
- [ ] Save changes.
- [ ] Verify that incoming values update properties.
- [ ] Verify reverse control by changing linked osysHome properties.

---

## How Discovery Works for Users

You do not manually add most devices in the UI. The module creates them when it receives Xiaomi packets with `sid`.

Initial fields filled automatically:

- `sid`
- `model` -> `type`
- auto title (`<Model> <YYYY-MM-DD>`)
- `gate_ip`
- `token` (when present)

For some types the plugin creates default command records:

| Device type | Auto-created commands |
| --- | --- |
| `gateway` | `ringtone` |
| `curtain` | `curtain_status` |

> [!TIP]
> If reverse control does not work, first check that gateway `Key` is set on the gateway device with the same `gate_ip`.

---

## Linking Commands to osysHome

In the device editor, every command can be linked to:

- `Linked object`
- `Linked property`
- `Linked method`

### Property link behavior

When a new Xiaomi value arrives, the module writes it into:

```text
Object.property
```

### Method link behavior

When a new Xiaomi value arrives, the module can call:

```text
Object.method
```

The called method receives the full decoded Xiaomi message payload.

### Typical examples

| Xiaomi command | Link target | Effect |
| --- | --- | --- |
| `temperature` | `Climate.outdoor_temp` | Keeps property in sync |
| `humidity` | `Climate.outdoor_humidity` | Keeps property in sync |
| `motion` | `Security.onMotion` (method) | Triggers automation method |
| `leak` | `Safety.waterLeak` (method) | Triggers emergency logic |
| `status` | `Door.contact` | Updates open/close status |

---

## Most Common Incoming Parameters

The plugin creates command records dynamically from Xiaomi messages.

Frequently used parameters:

| Parameter | Typical source | Value normalization |
| --- | --- | --- |
| `temperature` | temp/humidity sensor | divided by `100`, rounded to 2 digits |
| `humidity` | temp/humidity sensor | divided by `100`, rounded to 2 digits |
| `pressure_kpa` | pressure-capable sensors | `pressure / 1000` |
| `pressure_mm` | pressure-capable sensors | kPa converted to mmHg |
| `lux` / `illumination` | light sensors | saved as-is |
| `voltage` | battery devices | mV -> V |
| `battery_level` | battery devices | estimated `%` from mV |
| `motion` / `no_motion` | motion sensors | event-like values |
| `channel_0`, `channel_1` | wall switches/relays | normalized to `1/0` for on/off |
| `rgb`, `brightness` | gateway light | derived from gateway `rgb` integer |

---

## Reverse Control from osysHome

When osysHome property changes, `XiaomiHome` checks linked command records and sends `write` packets.

Supported control commands include:

- `status` for plugs (`plug`, `ctrl_86plug.aq1`)
- `channel_0`, `channel_1` for relays/switches
- `curtain_level` (`0..100`)
- `curtain_status` (`open`, `close`, `stop`, `auto`)
- `brightness` and `rgb` for gateway light
- `ringtone` for gateway alarm speaker (`mid[,vol]` or `stop`)

### Example: gateway light via property

If linked command is `rgb`, value is expected as hex color:

```text
#DA690A
```

If linked command is `brightness`, value is used as high-byte of Xiaomi `rgb` payload.

---

## Troubleshooting

### No devices appear

Check:

- host can receive UDP multicast on port `9898`;
- plugin cycle is running;
- Xiaomi gateway is in LAN protocol mode.

### Values are visible but links do nothing

Check:

- command has `Linked object` and `Linked property` or `Linked method`;
- selected object/member still exists in osysHome;
- changes were saved in the device editor.

### Reverse control does not affect device

Check:

- gateway device has correct `Key` and recent `token`;
- controlled subdevice and gateway share same `gate_ip`;
- linked command is one of supported write commands.

> [!WARNING]
> Without valid `gate_key` + `token` signature, Xiaomi gateways reject write commands.

---

## Notes and Limitations

- Device creation is event-driven; there is no separate manual discovery wizard.
- Some commands are event-like and may repeatedly call methods even if value does not change.
- Command deletion from UI exists, but the editor has a frontend typo in local array removal; page refresh may be needed after delete.
- Multicast receive timeout (`60s`) triggers socket reconnect automatically.

---

## See Also

- [Technical Reference](TECHNICAL_REFERENCE.md)
- [Module index](index.md)

[^1]: The plugin stores decoded Xiaomi parameters as rows in `xicommands`, not as a fixed schema per model.

