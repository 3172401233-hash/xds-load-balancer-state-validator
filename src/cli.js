#!/usr/bin/env node
/**
 * 用法: node src/cli.js <input.json> [--json]
 * 纯离线计算:只读取输入文件,不连接任何控制面。
 * 退出码: 0 = 无危险组合; 1 = 存在危险组合; 2 = 输入错误。
 */
import { readFile } from 'node:fs/promises';
import { validate } from './validator.js';

function printText(report) {
  console.log(`最新版本: ${report.latestVersion}`);
  console.log(`总体结论: ${report.safe ? '安全(无危险组合)' : '存在危险组合!'}`);
  console.log('');
  for (const proxy of report.proxies) {
    const v = proxy.effective.versions;
    console.log(`代理 ${proxy.name} (envoy ${proxy.proxyVersion})`);
    console.log(`  生效版本: CDS=${v.cds ?? '-'} EDS=${v.eds ?? '-'} RDS=${v.rds ?? '-'}`);
    console.log(`  生效配置: ${proxy.effective.clusters.length} 集群, ` +
      `${Object.values(proxy.effective.endpoints).reduce((n, e) => n + e.length, 0)} 端点, ` +
      `${proxy.effective.routes.length} 路由`);
    for (const f of proxy.findings) {
      console.log(`  [${f.severity}] ${f.type}: ${f.message}`);
    }
    console.log('');
  }
  if (report.fleetFindings.length > 0) {
    console.log('集群级发现:');
    for (const f of report.fleetFindings) console.log(`  [${f.severity}] ${f.message}`);
    console.log('');
  }
  if (report.dangerousCombinations.length > 0) {
    console.log('危险组合:');
    for (const f of report.dangerousCombinations) console.log(`  - ${f.message}`);
    console.log('');
  }
  if (report.rollbacks.length > 0) {
    console.log('需回滚资源:');
    for (const r of report.rollbacks) {
      console.log(`  - ${r.resource}: ${r.from ?? '-'} -> ${r.to ?? '(待选择一致版本)'} | ${r.reason}`);
    }
    console.log('');
  }
  if (report.degradations.length > 0) {
    console.log('安全降级方式(均不触发全量 panic):');
    for (const d of report.degradations) {
      console.log(`  - [${d.proxy}] ${d.scenario}: ${d.action}`);
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  const jsonFlag = args.includes('--json');
  const file = args.find((a) => !a.startsWith('--'));
  if (!file) {
    console.error('用法: node src/cli.js <input.json> [--json]');
    process.exit(2);
  }
  let input;
  try {
    input = JSON.parse(await readFile(file, 'utf8'));
  } catch (err) {
    console.error(`无法读取输入: ${err.message}`);
    process.exit(2);
  }
  let report;
  try {
    report = validate(input);
  } catch (err) {
    console.error(`校验失败: ${err.message}`);
    process.exit(2);
  }
  if (jsonFlag) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printText(report);
  }
  process.exit(report.safe ? 0 : 1);
}

main();
