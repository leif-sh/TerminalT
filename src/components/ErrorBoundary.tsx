import { Component, type ErrorInfo, type ReactNode } from 'react'

interface ErrorBoundaryProps {
  children: ReactNode
}

interface ErrorBoundaryState {
  error?: Error
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = {}

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('TerminalT view failed', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <main className="fatal-error" role="alert">
          <span>VIEW ERROR</span>
          <h1>界面未能正常加载</h1>
          <p>其他本地数据没有受到影响，请重新载入应用。</p>
          <details>
            <summary>技术详情</summary>
            <code>{this.state.error.message}</code>
          </details>
          <button type="button" onClick={() => window.location.reload()}>重新载入</button>
        </main>
      )
    }

    return this.props.children
  }
}
