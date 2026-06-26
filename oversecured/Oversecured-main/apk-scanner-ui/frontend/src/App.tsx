import { BrowserRouter } from 'react-router-dom'
import { AppRouter } from './router'
import { Layout } from './components/layout/Layout'
import { ErrorBoundary } from './components/common/ErrorBoundary'
import { ToastContainer } from './components/common/Toast'

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Layout>
          <AppRouter />
        </Layout>
        <ToastContainer />
      </BrowserRouter>
    </ErrorBoundary>
  )
}
