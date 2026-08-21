# 07 · HTML 可视化报告规范

## 报告结构

1. 基本信息卡（文件/包数/时长/规模）
2. 协议分布环形图（Chart.js doughnut）
3. Top 端点表
4. Top 域名表
5. 事件时间线（纵向时间轴）
6. IOC 清单表

## 图表类型

| 数据 | 图表 |
|------|------|
| 协议分布 | 环形图 doughnut |
| 时间趋势 | 折线图 line |
| 端点 Top N | 表格 |
| 会话关系 | 桑基图 sankey（可选） |

## 生成方式

html_report.py 读取 html_report.tpl.html 模板，占位符替换，无构建步骤。Chart.js 通过 CDN 加载（离线时图表不显示，但表格数据仍完整）。

## 降级策略

- CDN 不可达：图表不渲染，表格数据完整
- 模板缺失：回退到 Markdown 报告
- 全部失败：至少输出 IOC JSON
