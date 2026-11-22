import { useEffect, useState } from "react";
import { AlertTriangle, Check, GitBranch, Globe, Send, ShieldCheck, X } from "lucide-react";

type IntegrationSettings = {
  git_repositories: string[];
  telegram_chat_ids: string[];
  telegram_bot_configured: boolean;
  telegram_bot_available: boolean;
  webhook_hosts: string[];
};

type Props = { onClose: () => void };

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

const lines = (value: string) => value.split(/\r?\n/).map(item => item.trim()).filter(Boolean);

export default function IntegrationsSettings({ onClose }: Props) {
  const [gitRepositories, setGitRepositories] = useState("");
  const [telegramChatIds, setTelegramChatIds] = useState("");
  const [webhookHosts, setWebhookHosts] = useState("");
  const [botToken, setBotToken] = useState("");
  const [tokenConfigured, setTokenConfigured] = useState(false);
  const [tokenAvailable, setTokenAvailable] = useState(false);
  const [removeToken, setRemoveToken] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const applySettings = (data: IntegrationSettings) => {
    setGitRepositories((data.git_repositories || []).join("\n"));
    setTelegramChatIds((data.telegram_chat_ids || []).join("\n"));
    setWebhookHosts((data.webhook_hosts || []).join("\n"));
    setTokenConfigured(Boolean(data.telegram_bot_configured));
    setTokenAvailable(Boolean(data.telegram_bot_available));
  };

  useEffect(() => {
    let active = true;
    void request("/api/integrations")
      .then(async response => {
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Не удалось загрузить настройки интеграций.");
        if (active) applySettings(data as IntegrationSettings);
      })
      .catch(reason => {
        if (active) setError(reason instanceof Error ? reason.message : "Ошибка загрузки настроек.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const payload: Record<string, unknown> = {
        git_repositories: lines(gitRepositories),
        telegram_chat_ids: lines(telegramChatIds),
        webhook_hosts: lines(webhookHosts),
        remove_telegram_bot_token: removeToken,
      };
      if (botToken.trim()) payload.telegram_bot_token = botToken.trim();
      const response = await request("/api/integrations", {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Не удалось сохранить настройки.");
      applySettings(data as IntegrationSettings);
      setBotToken("");
      setRemoveToken(false);
      setNotice("Настройки интеграций сохранены для активной рабочей области.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Ошибка сохранения настроек.");
    } finally {
      setSaving(false);
    }
  };

  return <div className="template-library-backdrop integrations-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget && !saving) onClose(); }}>
    <section className="template-library-dialog integrations-dialog" role="dialog" aria-modal="true" aria-labelledby="integrations-title">
      <header className="template-library-header">
        <div><span className="eyebrow">WORKSPACE SETTINGS</span><h2 id="integrations-title"><ShieldCheck size={18}/> Интеграции платформы</h2><p>Подключения и разрешения сохраняются в активной рабочей области. Настраивать каждую ноду отдельно больше не требуется.</p></div>
        <button className="icon-button" onClick={onClose} aria-label="Закрыть настройки"><X size={16}/></button>
      </header>
      {loading ? <div className="integrations-loading">Загрузка настроек…</div> : <form className="integrations-form" onSubmit={save}>
        <section className="integration-setting">
          <div className="integration-setting-heading"><GitBranch size={16}/><div><b>Git-репозитории</b><small>Каждый URL — отдельная строка. Только HTTPS, без токенов и паролей.</small></div></div>
          <textarea value={gitRepositories} onChange={event => setGitRepositories(event.target.value)} rows={4} placeholder={"https://github.com/owner/repository\nhttps://github.com/another/project"} spellCheck={false}/>
        </section>
        <section className="integration-setting">
          <div className="integration-setting-heading"><Send size={16}/><div><b>Telegram</b><small>Токен бота хранится зашифрованным. Chat ID — по одному на строку.</small></div><span className={tokenConfigured ? "integration-status is-ready" : "integration-status"}>{tokenConfigured ? "ЗАШИФРОВАН" : tokenAvailable ? "LEGACY ENV" : "НЕ ПОДКЛЮЧЁН"}</span></div>
          <label className="integration-field-label">Токен Telegram Bot</label>
          <input type="password" autoComplete="new-password" value={botToken} onChange={event => setBotToken(event.target.value)} placeholder={tokenConfigured ? "Оставь пустым, чтобы не менять токен" : tokenAvailable ? "Токен уже доступен из legacy-конфигурации; можно перенести сюда" : "Вставь токен бота один раз"}/>
          {tokenConfigured && <label className="integration-remove-token"><input type="checkbox" checked={removeToken} onChange={event => setRemoveToken(event.target.checked)}/> Удалить сохранённый токен</label>}
          <label className="integration-field-label">Получатели (chat_id)</label>
          <textarea value={telegramChatIds} onChange={event => setTelegramChatIds(event.target.value)} rows={3} placeholder={"123456789\n-1001234567890"} spellCheck={false}/>
        </section>
        <section className="integration-setting">
          <div className="integration-setting-heading"><Globe size={16}/><div><b>Webhook-домены</b><small>Только hostname, без https://, пути, порта и wildcard. Каждый домен — отдельная строка.</small></div></div>
          <textarea value={webhookHosts} onChange={event => setWebhookHosts(event.target.value)} rows={3} placeholder={"hooks.example.com\nwebhook.site"} spellCheck={false}/>
        </section>
        <div className="integrations-security-note"><ShieldCheck size={14}/><span>INVEST продолжает проверять HTTPS, DNS и публичные IP-адреса webhook. Git-доступ ограничен только перечисленными репозиториями. Security Gate не отключается настройками интеграций.</span></div>
        {error && <div className="integrations-message is-error"><AlertTriangle size={14}/>{error}</div>}
        {notice && <div className="integrations-message is-success"><Check size={14}/>{notice}</div>}
        <footer className="integrations-actions"><button type="button" className="ghost" disabled={saving} onClick={onClose}>Закрыть</button><button type="submit" className="template-card-clone" disabled={saving}>{saving ? "Сохранение…" : "Сохранить настройки"}</button></footer>
      </form>}
    </section>
  </div>;
}
