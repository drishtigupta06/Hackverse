import { Component, type ReactNode, type ErrorInfo } from 'react'
import { AlertTriangle } from 'lucide-react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error?: Error
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('ErrorBoundary caught:', error, info.componentStack)
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <div className="flex flex-col items-center justify-center h-64 gap-3">
          <AlertTriangle className="w-10 h-10 text-red-400" />
          <h2 className="text-lg font-medium text-text-primary">Something went wrong</h2>
          <p className="text-sm text-text-secondary max-w-md text-center">
            {this.state.error?.message || 'An unexpected error occurred'}
          </p>
          <button
            onClick={() => this.setState({ hasError: false })}
            className="btn-primary text-sm mt-2"
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
