import { Navigate } from 'react-router-dom';
import { lastFolder } from '../utils/hooks';
import Folders from './Folders';

/** Sidebar "Members": vào thẳng folder vừa mở; chưa có thì cho chọn folder. */
export default function MembersIndex() {
  const id = lastFolder();
  return id ? <Navigate to={`/folders/${id}/members`} replace /> : <Folders pickFor="members" />;
}
