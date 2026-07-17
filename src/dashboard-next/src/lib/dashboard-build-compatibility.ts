export interface DashboardBuildCompatibility {
  compatible: boolean;
  client_build: string;
  server_build?: string;
  message?: string;
}

export function compareDashboardBuilds(
  serverBuild: string | undefined,
  clientBuild = __OVERWATCH_BUILD_INPUT_SHA__,
): DashboardBuildCompatibility {
  if (serverBuild === clientBuild) {
    return { compatible: true, client_build: clientBuild, server_build: serverBuild };
  }
  const serverLabel = serverBuild?.slice(0, 12) ?? 'legacy/unknown';
  return {
    compatible: false,
    client_build: clientBuild,
    ...(serverBuild ? { server_build: serverBuild } : {}),
    message: `Dashboard build ${clientBuild.slice(0, 12)} does not match server build ${serverLabel}.`,
  };
}
