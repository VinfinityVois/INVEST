import { useCallback, useEffect, useState } from "react";
import { MessageSquare, Send, Trash2, UserRound } from "lucide-react";

type Member = { user_id: string; email: string; role: string };
type Comment = { id: string; author_user_id: string; author_email: string; body: string; created_at: string };

async function requestJson(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...init, credentials: "include", headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "Операция с находкой не выполнена.");
  return data;
}

export default function FindingCollaboration({
  workflowId,
  fingerprint,
  currentUserId,
  assignedToUserId,
  onAssignedChange,
}: {
  workflowId: string;
  fingerprint: string;
  currentUserId: string;
  assignedToUserId?: string | null;
  onAssignedChange: () => void;
}) {
  const [members, setMembers] = useState<Member[]>([]);
  const [comments, setComments] = useState<Comment[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const [active, commentData] = await Promise.all([
        requestJson("/api/workspaces/active"),
        requestJson("/api/workflows/" + workflowId + "/findings/" + encodeURIComponent(fingerprint) + "/comments"),
      ]);
      const memberData = await requestJson("/api/workspaces/" + active.id + "/members");
      setMembers(memberData.items || []);
      setComments(commentData.items || []);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Не удалось загрузить комментарии.");
    }
  }, [workflowId, fingerprint]);

  useEffect(() => { void load(); }, [load]);

  const assign = async (userId: string) => {
    setBusy(true); setError("");
    try {
      await requestJson("/api/workflows/" + workflowId + "/findings/" + encodeURIComponent(fingerprint) + "/assignee", {
        method: "PATCH",
        body: JSON.stringify({ user_id: userId || null }),
      });
      onAssignedChange();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Не удалось назначить ответственного.");
    } finally { setBusy(false); }
  };

  const addComment = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!draft.trim()) return;
    setBusy(true); setError("");
    try {
      await requestJson("/api/workflows/" + workflowId + "/findings/" + encodeURIComponent(fingerprint) + "/comments", {
        method: "POST",
        body: JSON.stringify({ body: draft }),
      });
      setDraft("");
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Не удалось добавить комментарий.");
    } finally { setBusy(false); }
  };

  const deleteComment = async (comment: Comment) => {
    if (!window.confirm("Удалить свой комментарий?")) return;
    setBusy(true); setError("");
    try {
      await requestJson("/api/workflows/" + workflowId + "/findings/" + encodeURIComponent(fingerprint) + "/comments/" + comment.id, { method: "DELETE" });
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Не удалось удалить комментарий.");
    } finally { setBusy(false); }
  };

  return <section className="finding-collaboration">
    <div className="finding-collaboration-head"><b><UserRound size={13}/> Ответственный</b>
      <select value={assignedToUserId || ""} disabled={busy} onChange={event => void assign(event.target.value)}>
        <option value="">Не назначен</option>
        {members.filter(member => member.role !== "viewer").map(member => <option key={member.user_id} value={member.user_id}>{member.email} · {member.role}</option>)}
      </select>
    </div>
    <div className="finding-comments-heading"><b><MessageSquare size={13}/> Обсуждение</b><span>{comments.length}</span></div>
    {comments.length ? <div className="finding-comments-list">
      {comments.map(comment => <article key={comment.id}>
        <div><b>{comment.author_email}</b><time>{new Date(comment.created_at).toLocaleString()}</time>
          {comment.author_user_id === currentUserId && <button type="button" title="Удалить комментарий" disabled={busy} onClick={() => void deleteComment(comment)}><Trash2 size={11}/></button>}
        </div>
        <p>{comment.body}</p>
      </article>)}
    </div> : <p className="finding-comments-empty">Комментариев пока нет.</p>}
    <form onSubmit={addComment}>
      <textarea value={draft} onChange={event => setDraft(event.target.value)} placeholder="Добавить контекст, решение или ссылку на исправление…" maxLength={5000} rows={2}/>
      <button type="submit" disabled={busy || draft.trim().length < 1}><Send size={12}/> Отправить</button>
    </form>
    {error && <p className="finding-collaboration-error">{error}</p>}
  </section>;
}
