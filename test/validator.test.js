import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validate, computeEffectiveConfig } from '../src/validator.js';

const ep = (n) => ({ address: `10.0.0.${n}`, port: 8080 });
const key = (n) => `10.0.0.${n}:8080`;

function snapshot(version, { policy = 'ROUND_ROBIN', weights, endpoints, routes } = {}) {
  return {
    version,
    clusters: [
      { name: 'web', lbPolicy: policy, ...(weights ? { endpointWeights: weights } : {}) },
    ],
    endpoints: { web: endpoints },
    routes: routes ?? [{ name: 'web-route', prefix: '/', cluster: 'web' }],
  };
}

function proxy(name, { cds, eds, rds }) {
  return {
    name,
    proxyVersion: '1.31.0',
    cds: { version: cds, status: 'ACK' },
    eds: { version: eds, status: 'ACK' },
    rds: typeof rds === 'object' ? rds : { version: rds, status: 'ACK' },
  };
}

test('部分更新: EDS 已更新但 CDS 仍是旧 LB 策略 -> 危险组合', () => {
  const input = {
    history: [
      snapshot('v1', { policy: 'ROUND_ROBIN', weights: { [key(1)]: 1, [key(2)]: 1 }, endpoints: [ep(1), ep(2)] }),
      snapshot('v2', { policy: 'LEAST_REQUEST', weights: { [key(1)]: 1, [key(3)]: 4 }, endpoints: [ep(1), ep(3)] }),
    ],
    proxies: [proxy('p1', { cds: 'v1', eds: 'v2', rds: 'v2' })],
  };
  const report = validate(input);
  assert.equal(report.safe, false);
  const danger = report.dangerousCombinations.find((f) => f.type === 'EDS_AHEAD_OF_CDS_LB_POLICY');
  assert.ok(danger, '应检出 EDS 超前于 CDS 的危险组合');
  assert.equal(danger.cluster, 'web');
  assert.ok(report.rollbacks.some((r) => r.resource === 'eds/web' && r.to === 'v1'));
  assert.ok(report.degradations.every((d) => d.panic === false), '降级不得触发全量 panic');
});

test('策略切换: ROUND_ROBIN -> LEAST_REQUEST 未收敛时新端点按旧权重接流量', () => {
  const input = {
    history: [
      snapshot('v1', { policy: 'ROUND_ROBIN', endpoints: [ep(1), ep(2)] }),
      snapshot('v2', { policy: 'LEAST_REQUEST', endpoints: [ep(1), ep(2), ep(3)] }),
    ],
    proxies: [proxy('p1', { cds: 'v1', eds: 'v2', rds: 'v2' })],
  };
  const report = validate(input);
  assert.equal(report.safe, false);
  assert.ok(report.dangerousCombinations.some((f) => f.type === 'EDS_AHEAD_OF_CDS_LB_POLICY'));
});

test('部分更新但 LB 策略未变: 只提示版本偏斜,不判危险', () => {
  const input = {
    history: [
      snapshot('v1', { endpoints: [ep(1), ep(2)] }),
      snapshot('v2', { endpoints: [ep(1), ep(2), ep(3)] }),
    ],
    proxies: [proxy('p1', { cds: 'v1', eds: 'v2', rds: 'v2' })],
  };
  const report = validate(input);
  assert.equal(report.safe, true);
  assert.equal(report.dangerousCombinations.length, 0);
});

test('NACK: 代理拒绝新版本,回退到 lastAckedVersion 继续服务', () => {
  const input = {
    history: [
      snapshot('v1', { endpoints: [ep(1)] }),
      snapshot('v2', { endpoints: [ep(1), ep(2)] }),
    ],
    proxies: [
      proxy('p1', { cds: 'v2', eds: 'v2', rds: { version: 'v2', status: 'NACK', lastAckedVersion: 'v1' } }),
    ],
  };
  const report = validate(input);
  const p1 = report.proxies[0];
  assert.equal(p1.effective.versions.rds, 'v1');
  assert.ok(p1.findings.some((f) => f.type === 'CONFIG_NACKED'));
  assert.equal(report.safe, true, 'NACK 本身不是危险组合');
  assert.ok(report.degradations.some((d) => d.scenario.includes('NACK')));
});

test('NACK 且无 lastAckedVersion: 高位告警,该类资源为空但不崩溃', () => {
  const input = {
    history: [snapshot('v1', { endpoints: [ep(1)] })],
    proxies: [
      proxy('p1', { cds: 'v1', eds: 'v1', rds: { version: 'v1', status: 'NACK' } }),
    ],
  };
  const report = validate(input);
  const p1 = report.proxies[0];
  assert.equal(p1.effective.versions.rds, null);
  assert.equal(p1.effective.routes.length, 0);
  assert.ok(p1.findings.some((f) => f.type === 'NACK_WITHOUT_FALLBACK'));
});

test('端点删除: CDS 权重仍引用已删除端点 -> 危险 + 重新归一化降级', () => {
  const input = {
    history: [
      snapshot('v1', { weights: { [key(1)]: 1, [key(2)]: 3 }, endpoints: [ep(1), ep(2)] }),
      snapshot('v2', { weights: { [key(1)]: 1, [key(2)]: 3 }, endpoints: [ep(1)] }),
    ],
    proxies: [proxy('p1', { cds: 'v2', eds: 'v2', rds: 'v2' })],
  };
  const report = validate(input);
  assert.equal(report.safe, false);
  const danger = report.dangerousCombinations.find((f) => f.type === 'WEIGHT_REFERENCES_MISSING_ENDPOINT');
  assert.deepEqual(danger.missingEndpoints, [key(2)]);
  assert.ok(report.degradations.some((d) => d.action.includes('重新归一化')));
});

test('端点缺失: 集群无端点只局部降级,其余集群照常,绝不全量 panic', () => {
  const base = snapshot('v1', { endpoints: [ep(1)] });
  base.clusters.push({ name: 'api', lbPolicy: 'ROUND_ROBIN' });
  base.endpoints.api = [];
  base.routes.push({ name: 'api-route', prefix: '/api', cluster: 'api' });
  const input = { history: [base], proxies: [proxy('p1', { cds: 'v1', eds: 'v1', rds: 'v1' })] };
  const report = validate(input);
  const p1 = report.proxies[0];
  assert.ok(p1.findings.some((f) => f.type === 'CLUSTER_WITHOUT_ENDPOINTS' && f.cluster === 'api'));
  assert.equal(report.safe, true, '单集群无端点不是危险组合');
  const degradation = report.degradations.find((d) => d.scenario.includes('api'));
  assert.ok(degradation);
  assert.equal(degradation.panic, false);
  assert.ok(degradation.action.includes('其余集群照常服务'));
  assert.equal(p1.effective.endpoints.web.length, 1, 'web 集群端点不受影响');
});

test('路由指向不存在的集群 -> 危险组合,仅摘除该路由', () => {
  const v1 = snapshot('v1', { endpoints: [ep(1)] });
  const v2 = snapshot('v2', {
    endpoints: [ep(1)],
    routes: [
      { name: 'web-route', prefix: '/', cluster: 'web' },
      { name: 'new-route', prefix: '/new', cluster: 'ghost' },
    ],
  });
  const input = { history: [v1, v2], proxies: [proxy('p1', { cds: 'v1', eds: 'v1', rds: 'v2' })] };
  const report = validate(input);
  assert.equal(report.safe, false);
  assert.ok(report.dangerousCombinations.some((f) => f.type === 'ROUTE_UNKNOWN_CLUSTER' && f.cluster === 'ghost'));
  assert.ok(report.rollbacks.some((r) => r.resource === 'rds/new-route'));
});

test('全部收敛: 无危险组合、无降级项', () => {
  const input = {
    history: [snapshot('v1', { endpoints: [ep(1), ep(2)] })],
    proxies: [
      proxy('p1', { cds: 'v1', eds: 'v1', rds: 'v1' }),
      proxy('p2', { cds: 'v1', eds: 'v1', rds: 'v1' }),
    ],
  };
  const report = validate(input);
  assert.equal(report.safe, true);
  assert.equal(report.dangerousCombinations.length, 0);
  assert.equal(report.rollbacks.length, 0);
  assert.equal(report.degradations.length, 0);
  assert.equal(report.fleetFindings.length, 0);
});

test('代理间版本偏斜被标记为集群级发现', () => {
  const input = {
    history: [
      snapshot('v1', { endpoints: [ep(1)] }),
      snapshot('v2', { endpoints: [ep(1)] }),
    ],
    proxies: [
      proxy('p1', { cds: 'v1', eds: 'v1', rds: 'v1' }),
      proxy('p2', { cds: 'v2', eds: 'v2', rds: 'v2' }),
    ],
  };
  const report = validate(input);
  assert.ok(report.fleetFindings.some((f) => f.type === 'FLEET_VERSION_SKEW' && f.resource === 'CDS'));
});

test('computeEffectiveConfig: 引用未知版本时告警且不中断计算', () => {
  const historyIndex = new Map([['v1', snapshot('v1', { endpoints: [ep(1)] })]]);
  const findings = [];
  const effective = computeEffectiveConfig(
    proxy('p1', { cds: 'v9', eds: 'v1', rds: 'v1' }),
    historyIndex,
    findings,
  );
  assert.equal(effective.versions.cds, 'v9');
  assert.equal(effective.clusters.length, 0);
  assert.ok(findings.some((f) => f.type === 'UNKNOWN_VERSION'));
});

test('输入缺少 history 时抛出可读错误', () => {
  assert.throws(() => validate({ proxies: [] }), /history/);
});
