# Foundry Toolbox Package

`pounce-sentinel-toolbox.json` packages the Pounce Sentinel OpenAPI tool surface
for Microsoft Foundry Toolbox. It embeds `../openapi.yaml` under
`tools[].openapi.spec` and uses connection-based auth so Foundry can pass the
Azure Functions key without exposing it to prompts.

Create the project connection first:

```bash
azd ai connection create pounce-sentinel-api-key \
  --kind remote-tool \
  --target https://<function-app>.azurewebsites.net \
  --auth-type custom-keys \
  --custom-key "x-functions-key=<function-key>"
```

Create the toolbox:

```bash
azd ai toolbox create pounce-sentinel-policy --from-file integrations/foundry/toolbox/pounce-sentinel-toolbox.json
```

Regenerate the toolbox package after editing `integrations/foundry/openapi.yaml`:

```bash
python3 integrations/foundry/toolbox/render_toolbox.py
```
