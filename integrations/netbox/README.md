# NetBox Integration (Planned)

Automatic device sync between NetBox and VIRP O-Node device registry.

## Status: In Development

The NetBox integration will:

- Pull device inventory from NetBox as the single source of truth
- Generate `devices.json` for the O-Node automatically
- Sync device roles and tags to VIRP trust tier classification
- Encrypt output with `age` before writing to disk

## Configuration

Set environment variables:

```bash
NETBOX_URL=https://your-netbox-instance/api
NETBOX_TOKEN=your-api-token
OUTPUT_VIRP_DEVICES_JSON=/etc/virp/devices.json
AGE_KEY_PATH=/etc/virp/onode-key.txt
```

## See Also

- `integrations/prometheus/` — VIRP metrics exporter (working)
- `CONTRIBUTING.md` — How to contribute
