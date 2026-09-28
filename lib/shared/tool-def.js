/**
 * Tool-definition builder shared by the model-facing tools.
 *
 * Prefers the runtime's `defineTool` (spec DSL, strict argument validation)
 * when the host can resolve `@deepseek-ai/dsh-tools`; otherwise falls back to
 * the raw JSON-Schema registration shape this plugin has always used. Both
 * paths are generated from the same spec, so the advertised schema never
 * drifts between them.
 */
let cachedDefineTool = null
try {
  const mod = await import('@deepseek-ai/dsh-tools')
  cachedDefineTool = typeof mod.defineTool === 'function' ? mod.defineTool : null
} catch {
  cachedDefineTool = null
}

/** Compile one spec value node to raw JSON Schema (fallback path). */
function valueToRaw(node) {
  const out = { ...node }
  if (out.type === 'object' && out.properties) {
    const compiled = propertyMapToRaw(out.properties)
    out.properties = compiled.properties
    if (compiled.required) out.required = compiled.required
  }
  if (out.type === 'array' && out.items) out.items = valueToRaw(out.items)
  if (Array.isArray(out.oneOf)) out.oneOf = out.oneOf.map(valueToRaw)
  return out
}

/** Compile a spec property map to a raw object schema (fallback path). */
function propertyMapToRaw(map) {
  const properties = {}
  const required = []
  for (const [key, node] of Object.entries(map || {})) {
    const { required: isRequired, ...rest } = node
    properties[key] = valueToRaw(rest)
    if (isRequired === true) required.push(key)
  }
  const schema = { type: 'object', properties }
  if (required.length) schema.required = required
  return schema
}

/**
 * Build a registry-ready tool definition from the author spec.
 * @param {{ name: string, description: string, timeoutMs?: number,
 *           parameters: Record<string, object>,
 *           output: { schema: object, render: Function },
 *           execute: Function }} definition
 */
export function buildTool(definition) {
  if (cachedDefineTool) {
    const tool = cachedDefineTool(definition)
    // Keep the previous closed-parameters contract (the raw shape carried
    // additionalProperties: false; the spec DSL leaves the implicit root open).
    if (tool.parameters && tool.parameters.type === 'object') {
      tool.parameters.additionalProperties = false
    }
    return tool
  }
  const { parameters, output, ...rest } = definition
  return {
    ...rest,
    parameters: { ...propertyMapToRaw(parameters), additionalProperties: false },
    output: { ...output, schema: valueToRaw(output.schema) },
  }
}
