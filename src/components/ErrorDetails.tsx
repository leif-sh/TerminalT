import type { AppCommandError } from '../lib/ipc'

export function ErrorDetails({ error }: { error: AppCommandError }) {
  const details = [
    `时间：${new Date().toISOString()}`,
    `错误码：${error.code}`,
    `阶段：${error.category}`,
    `可重试：${error.retryable ? '是' : '否'}`,
    `详情：${sanitize(error.technicalDetails ?? error.message)}`,
  ].join('\n')
  return <details className="error-details"><summary>{error.message}</summary><pre>{details}</pre><button type="button" onClick={() => void navigator.clipboard.writeText(details)}>复制技术详情</button></details>
}

function sanitize(value: string): string {
  return value.replace(/(password|passphrase|secret|credential)[^\s,}]*/gi, '[REDACTED]')
}
