import { StrictMode, useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import '../index.css';
import * as api from '../api.js';
import Layout from '../layouts/Layout.jsx';
import TaskMonitor from '../pages/TaskMonitor.jsx';

function TasksEntry() {
    const [user, setUser] = useState("analyst");
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        api.getMe().then(u => setUser(u.username)).catch(() => {
            // Redirect to index if not logged in
            window.location.href = "/index.html";
        }).finally(() => setLoading(false));
    }, []);

    if (loading) return <div className="loading-center"><div className="spinner" /></div>;

    return (
        <Layout activePage="tasks" user={user}>
            <TaskMonitor />
        </Layout>
    );
}

createRoot(document.getElementById('root')).render(
    <StrictMode>
        <TasksEntry />
    </StrictMode>,
);
