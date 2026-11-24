import { useEffect, useState } from 'react';

/** Chạy fn khi deps đổi; trả {data, loading, error, reload}. */
export function useAsync(fn, deps = []) {
  const [s, setS] = useState({ data: null, loading: true, error: null });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    setS((p) => ({ ...p, loading: true, error: null }));
    fn().then(
      (data) => alive && setS({ data, loading: false, error: null }),
      (error) => alive && setS({ data: null, loading: false, error }),
    );
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { ...s, reload: () => setTick((t) => t + 1) };
}

export const rememberFolder = (id) => sessionStorage.setItem('medshare.lastFolder', id);
export const lastFolder = () => sessionStorage.getItem('medshare.lastFolder');
