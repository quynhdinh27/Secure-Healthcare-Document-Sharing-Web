import { Navigate, Route, Routes } from 'react-router-dom';
import { RequireAuth } from './auth/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Folders from './pages/Folders';
import FolderDetail from './pages/FolderDetail';
import MembersIndex from './pages/MembersIndex';
import UploadDocument from './pages/UploadDocument';
import DocumentDetails from './pages/DocumentDetails';
import VersionHistory from './pages/VersionHistory';
import SecurityKeys from './pages/SecurityKeys';
import KeyRotationLog from './pages/KeyRotationLog';
import AuditLog from './pages/AuditLog';
import Accounts from './pages/admin/Accounts';
import AccountDetails from './pages/admin/AccountDetails';
import AdminActivity from './pages/admin/AdminActivity';

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="folders" element={<Folders />} />
        <Route path="folders/:folderId" element={<FolderDetail />} />
        <Route path="folders/:folderId/members" element={<FolderDetail membersOnly />} />
        <Route path="folders/:folderId/upload" element={<UploadDocument />} />
        <Route path="folders/:folderId/documents/:documentId" element={<DocumentDetails />} />
        <Route path="folders/:folderId/documents/:documentId/versions" element={<VersionHistory />} />
        <Route path="members" element={<MembersIndex />} />
        <Route path="security" element={<SecurityKeys />} />
        <Route path="security/rotation-audit" element={<KeyRotationLog />} />
        <Route path="audit" element={<AuditLog />} />
        <Route path="admin/accounts" element={<RequireAuth admin><Accounts /></RequireAuth>} />
        <Route path="admin/accounts/:userId" element={<RequireAuth admin><AccountDetails /></RequireAuth>} />
        <Route path="admin/activity" element={<RequireAuth admin><AdminActivity /></RequireAuth>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
