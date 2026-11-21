import { useCallback, useEffect, useState } from "react";
import { Building2, Plus, Users, X, RefreshCw, Trash2, Crown, FolderOpen, ShieldCheck } from "lucide-react";

type Organization = { id: string; name: string; kind: string; role: "owner" | "admin" | "member" };
type Workspace = { id: string; name: string; organization_id: string; organization_name: string; role: string; is_default: boolean; active: boolean };
type Member = { user_id: string; email: string; role: string; is_active: boolean };
type ApiToken = { id: string; name: string; scopes: string[]; created_at: string; expires_at?: string | null; revoked_at?: string | null; last_used_at?: string | null };

async function api(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path, {
    ...init,
    credentials: "include",
    headers,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "Не удалось выполнить операцию.");
  return data;
}

export default function WorkspaceManager({ open, onClose, onChanged }: { open: boolean; onClose: () => void; onChanged: () => void }) {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [organizationId, setOrganizationId] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [organizationMembers, setOrganizationMembers] = useState<Member[]>([]);
  const [workspaceMembers, setWorkspaceMembers] = useState<Member[]>([]);
  const [apiTokens, setApiTokens] = useState<ApiToken[]>([]);
  const [tokenName, setTokenName] = useState("");
  const [tokenExpiry, setTokenExpiry] = useState("");
  const [tokenScopes, setTokenScopes] = useState<string[]>(["workflow:run", "run:read"]);
  const [issuedToken, setIssuedToken] = useState("");
  const [newOrganization, setNewOrganization] = useState("");
  const [newWorkspace, setNewWorkspace] = useState("");
  const [workspaceRename, setWorkspaceRename] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState("viewer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    const [orgData, workspaceData] = await Promise.all([
      api("/api/organizations"),
      api("/api/workspaces"),
    ]);
    setOrganizations(orgData.items || []);
    setWorkspaces(workspaceData.items || []);
    setOrganizationId(current => current && (orgData.items || []).some((item: Organization) => item.id === current) ? current : orgData.items?.[0]?.id || "");
    setWorkspaceId(current => current && (workspaceData.items || []).some((item: Workspace) => item.id === current) ? current : workspaceData.items?.find((item: Workspace) => item.active)?.id || workspaceData.items?.[0]?.id || "");
  }, []);

  useEffect(() => {
    if (!open) return;
    setError("");
    void load().catch(reason => setError(reason instanceof Error ? reason.message : "Ошибка загрузки."));
  }, [open, load]);

  useEffect(() => {
    if (!open || !organizationId) { setOrganizationMembers([]); return; }
    let active = true;
    api("/api/organizations/" + organizationId + "/members")
      .then(data => { if (active) setOrganizationMembers(data.items || []); })
      .catch(reason => { if (active) setError(reason instanceof Error ? reason.message : "Ошибка загрузки участников."); });
    return () => { active = false; };
  }, [open, organizationId]);

  useEffect(() => {
    setWorkspaceRename(workspaces.find(item => item.id === workspaceId)?.name || "");
  }, [workspaceId, workspaces]);

  useEffect(() => {
    const firstInOrganization = workspaces.find(item => item.organization_id === organizationId);
    if (firstInOrganization && !workspaces.some(item => item.id === workspaceId && item.organization_id === organizationId)) {
      setWorkspaceId(firstInOrganization.id);
    }
  }, [organizationId, workspaces, workspaceId]);

  useEffect(() => {
    if (!open || !workspaceId) { setWorkspaceMembers([]); return; }
    let active = true;
    api("/api/workspaces/" + workspaceId + "/members")
      .then(data => { if (active) setWorkspaceMembers(data.items || []); })
      .catch(reason => { if (active) setError(reason instanceof Error ? reason.message : "Ошибка загрузки участников."); });
    return () => { active = false; };
  }, [open, workspaceId]);

  useEffect(() => {
    if (!open || !workspaceId) { setApiTokens([]); return; }
    let active = true;
    api("/api/workspaces/" + workspaceId + "/tokens")
      .then(data => { if (active) setApiTokens(data.items || []); })
      .catch(() => { if (active) setApiTokens([]); });
    return () => { active = false; };
  }, [open, workspaceId]);

  const run = async (action: () => Promise<unknown>, success: string) => {
    setBusy(true); setError(""); setNotice("");
    try {
      await action();
      setNotice(success);
      await load();
      onChanged();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Операция не выполнена.");
    } finally { setBusy(false); }
  };

  const createOrganization = () => run(async () => {
    const created = await api("/api/organizations", { method: "POST", body: JSON.stringify({ name: newOrganization }) });
    setOrganizationId(created.id);
    setNewOrganization("");
  }, "Организация создана.");

  const createWorkspace = () => run(async () => {
    const created = await api("/api/workspaces", { method: "POST", body: JSON.stringify({ organization_id: organizationId, name: newWorkspace }) });
    setWorkspaceId(created.id);
    setNewWorkspace("");
  }, "Рабочая область создана.");

  const renameWorkspace = () => run(async () => {
    await api("/api/workspaces/" + workspaceId, {
      method: "PATCH", body: JSON.stringify({ name: workspaceRename }),
    });
  }, "Название Workspace обновлено.");

  const addMember = () => run(async () => {
    await api("/api/organizations/" + organizationId + "/members", {
      method: "POST",
      body: JSON.stringify({ email: memberEmail, workspace_id: workspaces.find(item => item.id === workspaceId)?.organization_id === organizationId ? workspaceId : null, workspace_role: memberRole }),
    });
    setMemberEmail("");
  }, "Участник добавлен.");

  const changeRole = (member: Member, role: string) => run(async () => {
    await api("/api/workspaces/" + workspaceId + "/members/" + member.user_id, {
      method: "PATCH", body: JSON.stringify({ role }),
    });
  }, "Роль участника обновлена.");

  const createToken = async () => {
    setBusy(true); setError(""); setNotice(""); setIssuedToken("");
    try {
      const data = await api("/api/workspaces/" + workspaceId + "/tokens", {
        method: "POST",
        body: JSON.stringify({ name: tokenName, scopes: tokenScopes, expires_at: tokenExpiry ? new Date(tokenExpiry + "T23:59:59Z").toISOString() : null }),
      });
      setIssuedToken(data.token);
      setTokenName("");
      setTokenExpiry("");
      const listed = await api("/api/workspaces/" + workspaceId + "/tokens");
      setApiTokens(listed.items || []);
      setNotice("API token создан. Скопируйте его сейчас: повторно показать секрет нельзя.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Не удалось создать API token.");
    } finally { setBusy(false); }
  };

  const revokeToken = (token: ApiToken) => {
    if (!window.confirm("Отозвать API token «" + token.name + "»? Интеграция перестанет работать.")) return;
    void run(async () => {
      await api("/api/workspaces/" + workspaceId + "/tokens/" + token.id, { method: "DELETE" });
      const listed = await api("/api/workspaces/" + workspaceId + "/tokens");
      setApiTokens(listed.items || []);
      setIssuedToken("");
    }, "API token отозван.");
  };

  const removeWorkspaceMember = (member: Member) => {
    if (!window.confirm("Удалить " + member.email + " из этой рабочей области?")) return;
    void run(() => api("/api/workspaces/" + workspaceId + "/members/" + member.user_id, { method: "DELETE" }), "Доступ к Workspace отозван.");
  };

  const removeOrganizationMember = (member: Member) => {
    if (member.role === "owner") { setError("Сначала передайте владение организацией."); return; }
    if (!window.confirm("Удалить " + member.email + " из организации и всех её Workspace?")) return;
    void run(() => api("/api/organizations/" + organizationId + "/members/" + member.user_id, { method: "DELETE" }), "Участник удалён из организации.");
  };

  const transferOwnership = (member: Member) => {
    if (member.role === "owner") return;
    if (!window.confirm("Передать владение организацией пользователю " + member.email + "? Вы станете администратором.")) return;
    void run(() => api("/api/organizations/" + organizationId + "/transfer-ownership", {
      method: "POST", body: JSON.stringify({ new_owner_user_id: member.user_id, confirm: true }),
    }), "Владение организацией передано.");
  };

  if (!open) return null;
  const selectedWorkspace = workspaces.find(item => item.id === workspaceId);
  const selectedOrganization = organizations.find(item => item.id === organizationId);
  const canManageOrganization = selectedOrganization?.role === "owner" || selectedOrganization?.role === "admin";
  const canManageWorkspace = selectedWorkspace?.role === "admin";

  return <div className="workspace-manager-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="workspace-manager" role="dialog" aria-modal="true" aria-labelledby="workspace-manager-title">
      <header className="workspace-manager-header">
        <div><span className="section-caption">ORGANIZATION / WORKSPACE</span><h2 id="workspace-manager-title"><Building2 size={17}/> Организации и доступы</h2></div>
        <button className="icon-button" type="button" onClick={onClose} aria-label="Закрыть"><X size={17}/></button>
      </header>
      {error && <div className="workspace-manager-alert">{error}</div>}
      {notice && <div className="workspace-manager-notice">{notice}</div>}
      <div className="workspace-manager-grid">
        <div className="workspace-manager-column">
          <section className="workspace-manager-section">
            <h3>Организации</h3>
            <select value={organizationId} onChange={event => setOrganizationId(event.target.value)} disabled={busy}>
              {organizations.map(item => <option key={item.id} value={item.id}>{item.name} · {item.role}</option>)}
            </select>
            <form onSubmit={event => { event.preventDefault(); void createOrganization(); }}>
              <input value={newOrganization} onChange={event => setNewOrganization(event.target.value)} placeholder="Название организации" maxLength={200} required/>
              <button type="submit" disabled={busy || newOrganization.trim().length < 2}><Plus size={13}/> Создать</button>
            </form>
          </section>
          <section className="workspace-manager-section">
            <h3><FolderOpen size={14}/> Workspace</h3>
            <select value={workspaceId} onChange={event => setWorkspaceId(event.target.value)} disabled={busy}>
              {workspaces.map(item => <option key={item.id} value={item.id}>{item.organization_name} / {item.name}</option>)}
            </select>
            {canManageOrganization && <form onSubmit={event => { event.preventDefault(); void createWorkspace(); }}>
              <input value={newWorkspace} onChange={event => setNewWorkspace(event.target.value)} placeholder="Название Workspace" maxLength={200} required/>
              <button type="submit" disabled={busy || newWorkspace.trim().length < 2 || !organizationId}><Plus size={13}/> Добавить</button>
            </form>}
            {canManageWorkspace && <form onSubmit={event => { event.preventDefault(); void renameWorkspace(); }}>
              <input value={workspaceRename} onChange={event => setWorkspaceRename(event.target.value)} placeholder="Переименовать Workspace" maxLength={200} required/>
              <button type="submit" disabled={busy || workspaceRename.trim().length < 2 || workspaceRename === selectedWorkspace?.name}>Сохранить имя</button>
            </form>}
            {selectedWorkspace && <p className="workspace-manager-hint">Текущая роль: <b>{selectedWorkspace.role}</b>{selectedWorkspace.active ? " · активная область" : ""}</p>}
          </section>
          <section className="workspace-manager-section">
            <h3><Users size={14}/> Участники организации</h3>
            <div className="workspace-manager-members">
              {organizationMembers.map(member => <div className="workspace-manager-member" key={member.user_id}>
                <span><b>{member.email}</b><small>{member.role}{member.is_active ? "" : " · заблокирован"}</small></span>
                {canManageOrganization && member.role !== "owner" && <div>
                  <button type="button" title="Передать владение" disabled={busy} onClick={() => transferOwnership(member)}><Crown size={13}/></button>
                  <button type="button" title="Удалить из организации" disabled={busy} onClick={() => removeOrganizationMember(member)}><Trash2 size={13}/></button>
                </div>}
              </div>)}
              {organizationMembers.length === 0 && <p className="workspace-manager-hint">Нет участников.</p>}
            </div>
          </section>
        </div>
        <div className="workspace-manager-column">
          <section className="workspace-manager-section">
            <h3><ShieldCheck size={14}/> Добавить участника</h3>
            <form className="workspace-manager-add-member" onSubmit={event => { event.preventDefault(); void addMember(); }}>
              <input type="email" value={memberEmail} onChange={event => setMemberEmail(event.target.value)} placeholder="Email существующего аккаунта" maxLength={320} required/>
              <select value={memberRole} onChange={event => setMemberRole(event.target.value)}>
                <option value="viewer">Viewer · просмотр</option>
                <option value="analyst">Analyst · findings</option>
                <option value="editor">Editor · workflow</option>
                <option value="admin">Admin · управление</option>
              </select>
              <button type="submit" disabled={busy || !canManageOrganization || !organizationId}><Plus size={13}/> Добавить в организацию и Workspace</button>
              <small>Добавляется существующий аккаунт. Приглашения по email пока не включены.</small>
            </form>
          </section>
          <section className="workspace-manager-section">
            <h3><ShieldCheck size={14}/> API Tokens / CI</h3>
            {canManageWorkspace && <>
              <form className="workspace-manager-add-member" onSubmit={event => { event.preventDefault(); void createToken(); }}>
                <input value={tokenName} onChange={event => setTokenName(event.target.value)} placeholder="Название токена" maxLength={120} required/>
                <label className="workspace-token-expiry">Срок действия (по умолчанию 90 дней)<input type="date" value={tokenExpiry} onChange={event => setTokenExpiry(event.target.value)}/></label>
                <div className="workspace-token-scopes">
                  {[
                    ["workflow:run", "Запуск workflow"],
                    ["run:read", "Статус запусков"],
                    ["template:publish", "Публикация шаблонов"],
                  ].map(([scope, label]) => <label key={scope}><input type="checkbox" checked={tokenScopes.includes(scope)} onChange={event => setTokenScopes(current => event.target.checked ? [...current, scope] : current.filter(item => item !== scope))}/>{label}</label>)}
                </div>
                <button type="submit" disabled={busy || tokenName.trim().length < 2 || tokenScopes.length === 0}><Plus size={13}/> Создать токен</button>
              </form>
              {issuedToken && <div className="workspace-issued-token"><b>Секрет показан один раз</b><code>{issuedToken}</code><button type="button" onClick={() => void navigator.clipboard.writeText(issuedToken)}>Копировать</button></div>}
              <div className="workspace-manager-members">
                {apiTokens.map(token => <div className="workspace-manager-member" key={token.id}>
                  <span><b>{token.name}</b><small>{token.scopes.join(" · ")}{token.revoked_at ? " · отозван" : token.expires_at ? " · до " + new Date(token.expires_at).toLocaleDateString() : ""}</small></span>
                  {!token.revoked_at && <button type="button" title="Отозвать токен" disabled={busy} onClick={() => revokeToken(token)}><Trash2 size={13}/></button>}
                </div>)}
                {apiTokens.length === 0 && <p className="workspace-manager-hint">Токены ещё не созданы.</p>}
              </div>
            </>}
            {!canManageWorkspace && <p className="workspace-manager-hint">Создавать и отзывать токены может только администратор Workspace.</p>}
          </section>
          <section className="workspace-manager-section">
            <h3><Users size={14}/> Доступ к выбранному Workspace</h3>
            <div className="workspace-manager-members">
              {workspaceMembers.map(member => <div className="workspace-manager-member" key={member.user_id}>
                <span><b>{member.email}</b><small>{member.is_active ? "Активен" : "Заблокирован"}</small></span>
                {canManageWorkspace ? <div>
                  <select value={member.role} disabled={busy} onChange={event => changeRole(member, event.target.value)}>
                    <option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="editor">Editor</option><option value="admin">Admin</option>
                  </select>
                  <button type="button" title="Отозвать доступ" disabled={busy} onClick={() => removeWorkspaceMember(member)}><Trash2 size={13}/></button>
                </div> : <small className="workspace-manager-role">{member.role}</small>}
              </div>)}
              {workspaceMembers.length === 0 && <p className="workspace-manager-hint">Нет прямых участников. Владельцы и администраторы организации имеют унаследованный доступ.</p>}
            </div>
          </section>
        </div>
      </div>
      <footer className="workspace-manager-footer">
        <button type="button" className="ghost" disabled={busy} onClick={() => void load().catch(reason => setError(String(reason)))}><RefreshCw size={13}/> Обновить</button>
        <button type="button" onClick={onClose}>Готово</button>
      </footer>
    </section>
  </div>;
}
