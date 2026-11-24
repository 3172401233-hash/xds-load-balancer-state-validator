/**
 * xDS 状态组合校验器(纯离线计算,不连接任何控制面)。
 *
 * 输入:资源版本历史(history)、每个代理的 CDS/EDS/RDS 版本与 ACK/NACK 状态。
 * 输出:每个代理的实际生效配置、危险组合、需回滚资源、安全降级方式。
 */

export const TYPES = ['cds', 'eds', 'rds'];

export const SEVERITY = Object.freeze({
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
});

function endpointKey(endpoint) {
  return `${endpoint.address}:${endpoint.port}`;
}

function endpointSet(endpoints) {
  return new Set((endpoints ?? []).map(endpointKey));
}

function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const item of a) if (!b.has(item)) return false;
  return true;
}

/** LB 策略签名:策略 + 权重表,用于判断"策略是否仍是旧版本"。 */
function lbSignature(cluster) {
  if (!cluster) return null;
  return JSON.stringify({
    policy: cluster.lbPolicy ?? null,
    weights: cluster.endpointWeights ?? null,
  });
}

/**
 * 计算某个代理某类资源的生效版本。
 * ACK -> 当前版本;NACK -> 回退到 lastAckedVersion(最后确认的版本)。
 */
export function effectiveVersionOf(status, type, proxyName, findings) {
  if (!status || typeof status.version !== 'string') {
    findings.push({
      type: 'MISSING_STATUS',
      severity: SEVERITY.MEDIUM,
      proxy: proxyName,
      message: `代理 ${proxyName} 缺少 ${type.toUpperCase()} 状态,该类资源按"未配置"处理`,
    });
    return null;
  }
  if (status.status === 'NACK') {
    if (!status.lastAckedVersion) {
      findings.push({
        type: 'NACK_WITHOUT_FALLBACK',
        severity: SEVERITY.HIGH,
        proxy: proxyName,
        message: `代理 ${proxyName} NACK 了 ${type.toUpperCase()} ${status.version} 且没有 lastAckedVersion,该类资源可能为空`,
      });
      return null;
    }
    return status.lastAckedVersion;
  }
  return status.version;
}

/** 计算单个代理的实际生效配置。 */
export function computeEffectiveConfig(proxy, historyIndex, findings) {
  const effective = { versions: {}, clusters: [], endpoints: {}, routes: [] };
  for (const type of TYPES) {
    const version = effectiveVersionOf(proxy[type], type, proxy.name, findings);
    effective.versions[type] = version;
    if (version === null) continue;
    const snapshot = historyIndex.get(version);
    if (!snapshot) {
      findings.push({
        type: 'UNKNOWN_VERSION',
        severity: SEVERITY.HIGH,
        proxy: proxy.name,
        message: `代理 ${proxy.name} 引用了历史中不存在的 ${type.toUpperCase()} 版本 ${version}`,
      });
      continue;
    }
    if (type === 'cds') effective.clusters = snapshot.clusters ?? [];
    if (type === 'eds') effective.endpoints = snapshot.endpoints ?? {};
    if (type === 'rds') effective.routes = snapshot.routes ?? [];
  }
  return effective;
}

function indexHistory(history) {
  const map = new Map();
  history.forEach((snapshot, index) => {
    if (map.has(snapshot.version)) {
      throw new Error(`history 中版本重复: ${snapshot.version}`);
    }
    map.set(snapshot.version, { ...snapshot, index });
  });
  return map;
}

function versionOrder(historyIndex, version) {
  const snapshot = historyIndex.get(version);
  return snapshot ? snapshot.index : -1;
}

/**
 * 主入口:校验整个输入,返回报告。
 * 原则:任何单一资源的缺失/异常只产生局部降级,绝不抛出、绝不触发全量 panic。
 */
export function validate(input) {
  if (!input || !Array.isArray(input.history) || input.history.length === 0) {
    throw new Error('输入必须包含非空 history 数组');
  }
  const proxies = Array.isArray(input.proxies) ? input.proxies : [];
  const historyIndex = indexHistory(input.history);
  const latest = input.history[input.history.length - 1];

  const report = {
    generatedAt: new Date().toISOString(),
    latestVersion: latest.version,
    proxies: [],
    dangerousCombinations: [],
    rollbacks: [],
    degradations: [],
    fleetFindings: [],
    safe: true,
  };

  for (const proxy of proxies) {
    const findings = [];
    const effective = computeEffectiveConfig(proxy, historyIndex, findings);
    const proxyReport = {
      name: proxy.name,
      proxyVersion: proxy.proxyVersion ?? 'unknown',
      effective,
      findings,
    };
    report.proxies.push(proxyReport);

    checkNack(proxy, effective, latest, findings, report);
    checkEdsAheadOfCds(proxy, effective, historyIndex, latest, findings, report);
    checkRouteClusters(proxy, effective, findings, report);
    checkClusterEndpoints(proxy, effective, findings, report);
    checkWeightConsistency(proxy, effective, findings, report);
  }

  checkFleetSkew(report);
  report.safe = report.dangerousCombinations.length === 0;
  return report;
}

function pushDanger(report, findings, finding) {
  findings.push(finding);
  if (finding.severity === SEVERITY.HIGH) {
    report.dangerousCombinations.push(finding);
  }
}

function addRollback(report, resource, from, to, reason) {
  report.rollbacks.push({ resource, from, to, reason });
}

function addDegradation(report, proxy, scenario, action) {
  report.degradations.push({ proxy, scenario, action, panic: false });
}

/** NACK:代理停留在旧配置,标记偏离但不视为危险组合。 */
function checkNack(proxy, effective, latest, findings, report) {
  for (const type of TYPES) {
    const status = proxy[type];
    if (status?.status !== 'NACK') continue;
    findings.push({
      type: 'CONFIG_NACKED',
      severity: SEVERITY.MEDIUM,
      proxy: proxy.name,
      message: `代理 ${proxy.name} NACK 了 ${type.toUpperCase()} ${status.version},` +
        `仍运行旧版本 ${effective.versions[type] ?? '(空)'}(最新为 ${latest.version})`,
    });
    addDegradation(
      report,
      proxy.name,
      `${type.toUpperCase()} 更新被拒绝(NACK)`,
      `保持旧版本 ${effective.versions[type] ?? '(空)'} 继续服务;修复配置后重推,不要强制清空该类资源`,
    );
  }
}

/**
 * 核心场景:端点列表已更新(EDS 新版本),但 LB 策略仍是旧版本(CDS 未跟上),
 * 导致新端点按错误权重接收流量。
 */
function checkEdsAheadOfCds(proxy, effective, historyIndex, latest, findings, report) {
  const cdsVersion = effective.versions.cds;
  const edsVersion = effective.versions.eds;
  if (!cdsVersion || !edsVersion) return;
  const cdsOrder = versionOrder(historyIndex, cdsVersion);
  const edsOrder = versionOrder(historyIndex, edsVersion);
  if (cdsOrder < 0 || edsOrder < 0 || edsOrder <= cdsOrder) return;

  const cdsSnapshot = historyIndex.get(cdsVersion);
  const edsSnapshotAtCds = historyIndex.get(cdsVersion);
  const latestClusters = new Map((latest.clusters ?? []).map((c) => [c.name, c]));

  for (const cluster of effective.clusters) {
    const latestCluster = latestClusters.get(cluster.name);
    if (!latestCluster) continue;
    const policyStale = lbSignature(cluster) !== lbSignature(latestCluster);
    const oldEndpoints = endpointSet(edsSnapshotAtCds.endpoints?.[cluster.name]);
    const newEndpoints = endpointSet(effective.endpoints[cluster.name]);
    const endpointsChanged = !setsEqual(oldEndpoints, newEndpoints);
    if (!policyStale || !endpointsChanged) continue;

    pushDanger(report, findings, {
      type: 'EDS_AHEAD_OF_CDS_LB_POLICY',
      severity: SEVERITY.HIGH,
      proxy: proxy.name,
      cluster: cluster.name,
      message:
        `代理 ${proxy.name} 集群 ${cluster.name}:端点已按 EDS ${edsVersion} 更新,` +
        `但 LB 策略仍是 CDS ${cdsVersion} 的旧版本(最新为 ${latest.version}),` +
        `新端点将按旧策略/旧权重接收流量`,
    });
    addRollback(
      report,
      `eds/${cluster.name}`,
      edsVersion,
      cdsVersion,
      `回滚 EDS 到与 CDS ${cdsVersion} 一致的版本,或先推进 CDS 到 ${latest.version} 再放开端点变更`,
    );
    addDegradation(
      report,
      proxy.name,
      `集群 ${cluster.name} 端点超前于 LB 策略`,
      '冻结该集群的端点推送;在 CDS 收敛前按旧权重在旧端点子集内重新归一化分流,新端点暂不接流量',
    );
  }
}

/** RDS 引用了生效 CDS 中不存在的集群 -> 该路由 404/503,但其余路由不受影响。 */
function checkRouteClusters(proxy, effective, findings, report) {
  const known = new Set(effective.clusters.map((c) => c.name));
  for (const route of effective.routes) {
    if (known.has(route.cluster)) continue;
    pushDanger(report, findings, {
      type: 'ROUTE_UNKNOWN_CLUSTER',
      severity: SEVERITY.HIGH,
      proxy: proxy.name,
      route: route.name,
      cluster: route.cluster,
      message: `代理 ${proxy.name} 路由 ${route.name}(${route.prefix ?? '/'})指向生效 CDS 中不存在的集群 ${route.cluster}`,
    });
    addRollback(
      report,
      `rds/${route.name}`,
      effective.versions.rds,
      null,
      '回滚 RDS 到引用已存在集群的版本,或先推送对应 CDS 集群',
    );
    addDegradation(
      report,
      proxy.name,
      `路由 ${route.name} 指向缺失集群 ${route.cluster}`,
      '仅摘除该路由(返回 404),其余路由与集群继续正常服务',
    );
  }
}

/** 集群在生效 EDS 中没有端点:局部降级,绝不触发全量 panic。 */
function checkClusterEndpoints(proxy, effective, findings, report) {
  for (const cluster of effective.clusters) {
    const endpoints = effective.endpoints[cluster.name] ?? [];
    if (endpoints.length > 0) continue;
    findings.push({
      type: 'CLUSTER_WITHOUT_ENDPOINTS',
      severity: SEVERITY.MEDIUM,
      proxy: proxy.name,
      cluster: cluster.name,
      message: `代理 ${proxy.name} 集群 ${cluster.name} 在生效 EDS 中没有任何端点`,
    });
    addDegradation(
      report,
      proxy.name,
      `集群 ${cluster.name} 无端点`,
      '仅将该集群移出负载均衡轮换(其路由返回 503),其余集群照常服务;禁止因单集群端点缺失而拒绝全部流量',
    );
  }
}

/** CDS 权重引用了生效 EDS 中已被删除的端点(端点删除场景)。 */
function checkWeightConsistency(proxy, effective, findings, report) {
  for (const cluster of effective.clusters) {
    const weights = cluster.endpointWeights;
    if (!weights) continue;
    const available = endpointSet(effective.endpoints[cluster.name]);
    const missing = Object.keys(weights).filter((key) => !available.has(key));
    if (missing.length === 0) continue;
    pushDanger(report, findings, {
      type: 'WEIGHT_REFERENCES_MISSING_ENDPOINT',
      severity: SEVERITY.HIGH,
      proxy: proxy.name,
      cluster: cluster.name,
      missingEndpoints: missing,
      message:
        `代理 ${proxy.name} 集群 ${cluster.name}:CDS 权重指向已删除的端点 ` +
        `${missing.join(', ')},对应权重的流量将被丢弃`,
    });
    addRollback(
      report,
      `eds/${cluster.name}`,
      effective.versions.eds,
      null,
      '恢复被删除的端点,或回滚 CDS 权重使其只引用现存端点',
    );
    addDegradation(
      report,
      proxy.name,
      `集群 ${cluster.name} 权重指向缺失端点`,
      '在现存端点上重新归一化权重,缺失端点的权重按比例转移,而不是让该部分流量黑洞',
    );
  }
}

/** 版本偏斜:同类资源在代理间生效版本不一致。 */
function checkFleetSkew(report) {
  for (const type of TYPES) {
    const byVersion = new Map();
    for (const proxy of report.proxies) {
      const version = proxy.effective.versions[type] ?? '(none)';
      if (!byVersion.has(version)) byVersion.set(version, []);
      byVersion.get(version).push(proxy.name);
    }
    if (byVersion.size <= 1) continue;
    report.fleetFindings.push({
      type: 'FLEET_VERSION_SKEW',
      severity: SEVERITY.LOW,
      resource: type.toUpperCase(),
      versions: Object.fromEntries(byVersion),
      message: `${type.toUpperCase()} 在代理间生效版本不一致: ` +
        [...byVersion.entries()].map(([v, ps]) => `${v} -> [${ps.join(', ')}]`).join('; '),
    });
  }
}
