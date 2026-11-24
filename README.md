# xds-load-balancer-state-validator

离线校验 xDS(CDS / EDS / RDS)状态组合:输入资源版本、ACK/NACK、端点、集群、
路由、LB 策略和代理版本,计算每个代理的**实际生效配置**,并输出**危险组合、
需回滚资源与安全降级方式**。

> **本工具不连接任何控制面。** 它是纯离线计算器:只读取一份 JSON 输入文件,
> 不发起任何网络请求,不与 Envoy / Istiod / go-control-plane 等控制面通信。
> 输入数据由使用者从自己的控制面导出(offline 快照)。

## 环境

- Node.js >= 24.16.0(开发验证版本:v24.16.0)
- 无第三方依赖

## 使用

```bash
node src/cli.js examples/dangerous-mix.json          # 文本报告
node src/cli.js examples/dangerous-mix.json --json   # JSON 报告
npm test                                             # node --test
```

退出码:`0` 无危险组合;`1` 存在危险组合;`2` 输入错误。

## 输入格式

```jsonc
{
  "history": [                       // 资源版本历史,按时间升序,最后一项为最新版本
    {
      "version": "v10",
      "clusters": [                  // CDS:集群 + LB 策略 + 可选端点权重
        { "name": "web", "lbPolicy": "ROUND_ROBIN",
          "endpointWeights": { "10.0.0.1:8080": 1 } }
      ],
      "endpoints": {                 // EDS:集群名 -> 端点列表
        "web": [ { "address": "10.0.0.1", "port": 8080 } ]
      },
      "routes": [                    // RDS:路由 -> 集群
        { "name": "web-route", "prefix": "/", "cluster": "web" }
      ]
    }
  ],
  "proxies": [
    {
      "name": "proxy-a",
      "proxyVersion": "1.31.0",
      "cds": { "version": "v10", "status": "ACK" },
      "eds": { "version": "v11", "status": "ACK" },
      "rds": { "version": "v11", "status": "NACK", "lastAckedVersion": "v10" }
    }
  ]
}
```

生效版本规则:`ACK` 取当前版本;`NACK` 回退到 `lastAckedVersion`。

## 检测规则

| 规则 | 级别 | 说明 |
| --- | --- | --- |
| `EDS_AHEAD_OF_CDS_LB_POLICY` | high | 端点已更新但 LB 策略仍是旧版本,新端点按错误权重接收流量 |
| `WEIGHT_REFERENCES_MISSING_ENDPOINT` | high | CDS 权重指向已删除的端点,对应流量被丢弃 |
| `ROUTE_UNKNOWN_CLUSTER` | high | RDS 路由指向生效 CDS 中不存在的集群 |
| `CLUSTER_WITHOUT_ENDPOINTS` | medium | 集群无端点:仅移出轮换,**不触发全量 panic** |
| `CONFIG_NACKED` | medium | 代理 NACK 后停留在旧配置 |
| `FLEET_VERSION_SKEW` | low | 同类资源在代理间生效版本不一致 |

核心原则:资源分别收敛不代表组合安全;任何单一资源异常只做局部降级
(摘除该路由 / 该集群、权重重新归一化),绝不因缺失端点而拒绝全部流量。

## 项目结构

- `src/validator.js` — 校验核心:生效配置计算 + 全部检测规则
- `src/cli.js` — 命令行入口
- `test/validator.test.js` — `node --test` 测试(部分更新、NACK、端点删除、策略切换等)
- `examples/dangerous-mix.json` — 危险组合示例输入
