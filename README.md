# secpeel (working name)

secpeel identifies the open-source components inside compiled artifacts and reports their known vulnerabilities. It works on executables, libraries, JARs, firmware, container images and installers, without source code or build files.

The project is in the design phase. The name is a placeholder.

## Approach

Identification and vulnerability lookup are deterministic. The tool unpacks an artifact, collects evidence from every file, matches that evidence to component versions, and looks up advisories for those exact versions in curated databases. A language model is used only at the end, to verify findings, explain them, and suggest next steps.

Unpacking and identification failures are reported explicitly. A file that could not be unpacked or identified is listed in the results instead of being skipped silently.

The component inventory is handed to [secdepth](https://github.com/kobaltoxid/secdepth), which checks whether each vulnerable component is reachable and writes the final report.

See the [design document](docs/design.md) once it is published.
