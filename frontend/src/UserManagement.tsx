import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Check, KeyRound, Lock, Plus, RefreshCw, Search, Shield, Users, X } from "lucide-react";

type ManagedUser = {
  id: string; email: string; role: "admin" | "user"; is_admin: boolean;
  is_active: boolean; active_sessions: number; created_at: string | null;
};
type SessionItem = {
  id: string; created_at: string | null; last_seen_at: string | null;
  expires_at: string; revoked: boolean; current: boolean;
};

type Props = { isAdmin: boolean; currentUserId: string; currentEmail: string; onProfileUpdated: (user: { id: string; email: string; is_admin: boolean }) => void; onClose: () => void; initialTab?: "profile" | "users" };

async function request(path: string, init?: RequestInit) {
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  if (response.status === 401) window.dispatchEvent(new Event("invest:unauthorized"));
  return response;
}

export default function UserManagement({ isAdmin, currentUserId, currentEmail, onProfileUpdated, onClose, initialTab = "profile" }: Props) {
  const [activeTab, setActiveTab] = useState<"profile" | "users">(initialTab === "users" && isAdmin ? "users" : "profile");
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [role, setRole] = useState("all");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(0);
  const [email, setEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newAdmin, setNewAdmin] = useState(false);
  const [editing, setEditing] = useState<Record<string, string>>({});
  const [profileEmail, setProfileEmail] = useState(currentEmail);
  const [profilePassword, setProfilePassword] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [nextPassword, setNextPassword] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  const loadUsers = useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ q: query, status, role, page: String(page), page_size: "20" });
      const response = await request("/api/admin/users?" + params.toString());
      if (!response.ok) throw new Error(response.status === 403 ? "Недостаточно прав для управления пользователями." : "Не удалось загрузить пользователей.");
      const data = await response.json();
      setUsers(data.items);
      setTotal(data.total);
      setPages(data.pages);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Ошибка загрузки.");
    } finally {
      setLoading(false);
    }
  }, [isAdmin, query, status, role, page]);

  const loadSessions = useCallback(async () => {
    try {
      const response = await request("/api/auth/sessions");
      if (!response.ok) throw new Error("Не удалось загрузить активные сессии.");
      const data = await response.json();
      setSessions(data.items);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Ошибка загрузки сессий.");
    }
  }, []);

  useEffect(() => { void loadUsers(); }, [loadUsers]);
  useEffect(() => { setProfileEmail(currentEmail); }, [currentEmail]);
  useEffect(() => { void loadSessions(); }, [loadSessions]);

  const mutateUser = async (id: string, changes: Record<string, unknown>) => {
    setSaving(true); setError(""); setNotice("");
    try {
      const response = await request("/api/admin/users/" + id, {
        method: "PATCH", body: JSON.stringify(changes),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Не удалось изменить пользователя.");
      if (typeof data.email === "string") setEditing(value => ({ ...value, [id]: data.email }));
      setNotice("Изменения сохранены.");
      await loadUsers();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Ошибка сохранения.");
    } finally { setSaving(false); }
  };

  const createUser = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true); setError(""); setNotice("");
    try {
      const response = await request("/api/admin/users", {
        method: "POST",
        body: JSON.stringify({ email, password: newPassword, is_admin: newAdmin }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Не удалось создать пользователя.");
      setEmail(""); setNewPassword(""); setNewAdmin(false); setPage(1);
      setNotice("Пользователь создан. Пароль отображается только в этом поле и не сохраняется в списке.");
      await loadUsers();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Ошибка создания.");
    } finally { setSaving(false); }
  };

  const updateProfile = async (event: React.FormEvent) => {
    event.preventDefault(); setSaving(true); setError(""); setNotice("");
    try {
      const response = await request("/api/auth/profile", {
        method: "PATCH", body: JSON.stringify({ email: profileEmail, current_password: profilePassword }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Не удалось обновить профиль.");
      setProfileEmail(data.email); setProfilePassword("");
      onProfileUpdated({ id: data.id, email: data.email, is_admin: data.is_admin });
      setNotice("Email профиля обновлён.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Ошибка обновления профиля.");
    } finally { setSaving(false); }
  };

  const changePassword = async (event: React.FormEvent) => {
    event.preventDefault(); setSaving(true); setError(""); setNotice("");
    try {
      const response = await request("/api/auth/password", {
        method: "POST", body: JSON.stringify({ current_password: currentPassword, new_password: nextPassword }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Не удалось сменить пароль.");
      setCurrentPassword(""); setNextPassword("");
      setNotice("Пароль изменён. Остальные сессии завершены.");
      await loadSessions();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Ошибка смены пароля.");
    } finally { setSaving(false); }
  };

  const revokeSession = async (id: string) => {
    setSaving(true); setError("");
    try {
      const response = await request("/api/auth/sessions/" + id, { method: "DELETE" });
      if (!response.ok) throw new Error("Не удалось завершить сессию.");
      await loadSessions();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Ошибка."); }
    finally { setSaving(false); }
  };

  const revokeOthers = async () => {
    setSaving(true); setError("");
    try {
      const response = await request("/api/auth/sessions", { method: "DELETE" });
      if (!response.ok) throw new Error("Не удалось завершить другие сессии.");
      await loadSessions(); setNotice("Все остальные сессии завершены.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Ошибка."); }
    finally { setSaving(false); }
  };

  return <div className="template-library-backdrop user-management-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="template-library-dialog user-management-dialog" role="dialog" aria-modal="true" aria-labelledby="user-management-title">
      <header className="template-library-header user-access-header">
        <div><span className="eyebrow">SECURITY PROFILE & ACCESS CONTROL</span><h2 id="user-management-title"><Shield size={18}/> Центр управления доступом и безопасностью</h2><p>Персональные настройки учётной записи и отдельное администрирование пользователей системы.</p></div>
        <button className="icon-button" onClick={onClose} aria-label="Закрыть"><X size={16}/></button>
      </header>
      <nav className="user-access-tabs" aria-label="Разделы управления доступом">
        <button type="button" className={activeTab === "profile" ? "active" : ""} onClick={() => setActiveTab("profile")}><Shield size={15}/> Мой профиль <span>ЛИЧНОЕ</span></button>
        {isAdmin && <button type="button" className={activeTab === "users" ? "active" : ""} onClick={() => setActiveTab("users")}><Users size={15}/> Управление пользователями <span>ADMIN · {total}</span></button>}
      </nav>
      {error && <div className="template-library-error"><AlertTriangle size={14}/><span>{error}</span><button onClick={() => { void loadUsers(); void loadSessions(); }}>Повторить</button></div>}
      {notice && <div className="user-management-notice"><Check size={14}/>{notice}</div>}
      <div className="user-management-content">
        {activeTab === "users" && isAdmin && <>
          <section className="user-management-section user-admin-intro">
            <div className="user-section-heading"><div><Users size={15}/><b>Управление пользователями и правами</b><small>{total} аккаунтов в системе</small></div><button className="ghost" onClick={() => void loadUsers()} disabled={loading}><RefreshCw size={13}/> Обновить</button></div>
            <p>Создание учётных записей, назначение системной роли и обратимая блокировка с отзывом активных сессий.</p>
          </section>
          <section className="user-management-section">
            <div className="user-section-heading"><div><Users size={15}/><b>Пользователи</b><small>{total} аккаунтов</small></div><button className="ghost" onClick={() => void loadUsers()} disabled={loading}><RefreshCw size={13}/> Обновить</button></div>
            <div className="user-filter-row">
              <label><Search size={13}/><input value={query} onChange={event => { setQuery(event.target.value); setPage(1); }} placeholder="Поиск по email"/></label>
              <select value={status} onChange={event => { setStatus(event.target.value); setPage(1); }}><option value="all">Все статусы</option><option value="active">Активные</option><option value="inactive">Заблокированные</option></select>
              <select value={role} onChange={event => { setRole(event.target.value); setPage(1); }}><option value="all">Все роли</option><option value="admin">Администраторы</option><option value="user">Пользователи</option></select>
            </div>
            <form className="user-create-form" onSubmit={createUser}>
              <input type="email" required maxLength={320} value={email} onChange={event => setEmail(event.target.value)} placeholder="email@example.com"/>
              <input type="password" required minLength={12} maxLength={1024} value={newPassword} onChange={event => setNewPassword(event.target.value)} placeholder="Временный пароль · от 12 символов"/>
              <label className="user-admin-check"><input type="checkbox" checked={newAdmin} onChange={event => setNewAdmin(event.target.checked)}/> Администратор</label>
              <button className="template-card-clone" disabled={saving}><Plus size={13}/> Создать</button>
            </form>
            <div className="user-table-wrap">
              {loading ? <div className="template-library-empty">Загрузка пользователей…</div> : users.map(item => <article className="user-row" key={item.id}>
                <div className="user-row-main"><b>{item.email}</b><span>{item.role === "admin" ? "ADMIN" : "USER"} · {item.active_sessions} сессий</span></div>
                <span className={"user-status " + (item.is_active ? "active" : "inactive")}>{item.is_active ? "Активен" : "Заблокирован"}</span>
                <div className="user-row-actions">
                  <button disabled={saving || item.id === currentUserId} title="Переключить роль" onClick={() => void mutateUser(item.id, { is_admin: !item.is_admin })}>{item.is_admin ? "Снять admin" : "Сделать admin"}</button>
                  <button disabled={saving || item.id === currentUserId} className={item.is_active ? "danger" : ""} onClick={() => void mutateUser(item.id, { is_active: !item.is_active })}>{item.is_active ? "Заблокировать" : "Разблокировать"}</button>
                </div>
                <div className="user-email-edit"><input aria-label={"Email " + item.email} value={editing[item.id] ?? item.email} onChange={event => setEditing(value => ({ ...value, [item.id]: event.target.value }))}/><button disabled={saving || !editing[item.id] || editing[item.id] === item.email} onClick={() => void mutateUser(item.id, { email: editing[item.id] })}>Сохранить email</button></div>
              </article>)}
              {!loading && !users.length && <div className="template-library-empty">Пользователи не найдены.</div>}
            </div>
            <div className="user-pagination"><span>Страница {page} из {Math.max(1, pages)} · {total} записей</span><div><button disabled={page <= 1 || loading} onClick={() => setPage(value => value - 1)}>Назад</button><button disabled={page >= pages || loading} onClick={() => setPage(value => value + 1)}>Далее</button></div></div>
            <p className="user-policy-note">Удаление аккаунта пока намеренно отключено: до внедрения владения данными применяется обратимая блокировка с отзывом всех его сессий.</p>
          </section>
        </>}
        {activeTab === "profile" && <>
        <section className="user-profile-banner">
          <div className="user-profile-avatar">{currentEmail.slice(0, 2).toUpperCase()}</div>
          <div><span className="eyebrow">ACCOUNT IDENTITY</span><b>{currentEmail}</b><small>{isAdmin ? "SYSTEM ADMINISTRATOR" : "STANDARD USER"} · УЧЁТНАЯ ЗАПИСЬ АКТИВНА</small></div>
          <span className="user-profile-online"><i/> ONLINE</span>
        </section>
        <div className="user-profile-grid">
        <section className="user-management-section user-profile-panel">
          <div className="user-section-heading"><div><Shield size={15}/><b>Личные данные профиля</b></div><small>РЕЖИМ РЕДАКТИРОВАНИЯ</small></div>
          <form className="user-password-form" onSubmit={updateProfile}>
            <input type="email" required maxLength={320} value={profileEmail} onChange={event => setProfileEmail(event.target.value)} placeholder="Email аккаунта"/>
            <input type="password" required maxLength={1024} autoComplete="current-password" value={profilePassword} onChange={event => setProfilePassword(event.target.value)} placeholder="Подтвердите текущим паролем"/>
            <button className="template-card-clone" disabled={saving || profileEmail.trim().toLowerCase() === currentEmail.toLowerCase()}><Check size={13}/> Сохранить профиль</button>
          </form>
        </section>
        </section>
        <div className="user-profile-security">
        <section className="user-management-section">
          <div className="user-section-heading"><div><Lock size={15}/><b>Активные сессии</b><small>{sessions.filter(item => !item.revoked).length} действующих</small></div><button className="ghost" disabled={saving} onClick={() => void revokeOthers()}>Завершить остальные</button></div>
          <div className="user-session-list">
            {sessions.map(item => <article className="user-session-row" key={item.id}><div><b>{item.current ? "Текущая сессия" : "Сессия устройства"}</b><small>Создана: {item.created_at ? new Date(item.created_at).toLocaleString("ru-RU") : "—"} · Истекает: {new Date(item.expires_at).toLocaleString("ru-RU")}</small></div><span className={item.revoked ? "revoked" : "active"}>{item.revoked ? "Завершена" : "Активна"}</span>{!item.revoked && <button disabled={saving || item.current} onClick={() => void revokeSession(item.id)}>Завершить</button>}</article>)}
            {!sessions.length && <div className="template-library-empty">Сессий пока нет.</div>}
          </div>
        </section>
        <section className="user-management-section">
          <div className="user-section-heading"><div><KeyRound size={15}/><b>Смена пароля</b></div></div>
          <form className="user-password-form" onSubmit={changePassword}>
            <input type="password" required maxLength={1024} autoComplete="current-password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} placeholder="Текущий пароль"/>
            <input type="password" required minLength={12} maxLength={1024} autoComplete="new-password" value={nextPassword} onChange={event => setNextPassword(event.target.value)} placeholder="Новый пароль · минимум 12 символов"/>
            <button className="template-card-clone" disabled={saving}><KeyRound size={13}/> Изменить пароль</button>
          </form>
        </section>
        </div>
        </div>
        </>}
      </div>
      <footer className="template-library-footer"><span>SERVER-SIDE PERMISSIONS · SESSION REVOCATION</span><button onClick={onClose}>Закрыть</button></footer>
    </section>
  </div>;
}
