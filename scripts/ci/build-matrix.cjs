// CI and releases compile the same Agent, rescue and Host targets.
const targets = {
  linux: ["amd64", "arm64", "386", "arm", "loong64"],
  windows: ["amd64", "arm64", "386"],
  darwin: ["amd64", "arm64"],
  freebsd: ["amd64", "arm64", "386", "arm"],
};

const platforms = Object.entries(targets);
const grouped = platforms.map(([goos, arches]) => ({ goos, arches: arches.join(" ") }));
const individual = platforms.flatMap(([goos, arches]) => arches.map(goarch => ({ goos, goarch })));
for (const [key, matrix] of Object.entries({ grouped, individual })) {
  console.log(`${key}=${JSON.stringify(matrix)}`);
}
