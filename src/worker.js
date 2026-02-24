import html from './index.html';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // =====================================================================
    // 🛡️ HASH SHA-256
    // =====================================================================
    async function hashPassword(text) {
      const msgUint8 = new TextEncoder().encode(text);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // =====================================================================
    // 🔐 VALIDAÇÃO DE USUÁRIO
    // =====================================================================
    async function authenticate(username, password) {
      const userRaw = await env.DB.get(`user:${username}`);
      if (!userRaw) return null;

      const user = JSON.parse(userRaw);
      const inputHash = await hashPassword(password);

      if (user.password !== inputHash) return null;

      return user;
    }

    // --- ROTA: FRONTEND ---
    if (request.method === "GET" && path === "/") {
      return new Response(html, {
        headers: { "Content-Type": "text/html;charset=UTF-8" },
      });
    }

    // --- ROTA: REGISTER ---
    if (request.method === "POST" && path === "/api/register") {
      try {
        const { username, password, token } = await request.json();

        if (!username || !password || !token) {
          return new Response(JSON.stringify({ error: "Dados incompletos." }), { status: 400 });
        }

        if (token !== env.REGISTRATION_TOKEN) {
          return new Response(JSON.stringify({ error: "Token inválido." }), { status: 403 });
        }

        const existing = await env.DB.get(`user:${username}`);
        if (existing) {
          return new Response(JSON.stringify({ error: "Usuário já existe." }), { status: 400 });
        }

        const hashedPassword = await hashPassword(password);

        const userData = {
          password: hashedPassword,
          data: {}
        };

        await env.DB.put(`user:${username}`, JSON.stringify(userData));

        return new Response(JSON.stringify({ success: true }));
      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro no registro." }), { status: 500 });
      }
    }

    // --- ROTA: LOGIN ---
    if (request.method === "POST" && path === "/api/login") {
      try {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const blockKey = `block:${ip}`;

        const attemptsRaw = await env.DB.get(blockKey);
        const attempts = attemptsRaw ? parseInt(attemptsRaw) : 0;

        if (attempts >= 5) {
          return new Response(JSON.stringify({
            error: "Bloqueado por excesso de tentativas."
          }), { status: 429 });
        }

        const { username, password } = await request.json();

        async function registerFailure() {
          await env.DB.put(blockKey, (attempts + 1).toString(), { expirationTtl: 900 });
        }

        const userRaw = await env.DB.get(`user:${username}`);

        if (!userRaw) {
          await registerFailure();
          return new Response(JSON.stringify({ error: "Credenciais inválidas." }), { status: 401 });
        }

        const user = JSON.parse(userRaw);
        const inputHash = await hashPassword(password);

        if (user.password !== inputHash) {
          await registerFailure();
          return new Response(JSON.stringify({ error: "Credenciais inválidas." }), { status: 401 });
        }

        await env.DB.delete(blockKey);

        return new Response(JSON.stringify({ success: true }));

      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro no login." }), { status: 500 });
      }
    }

    // --- ROTA: SALVAR (mantida) ---
    if (request.method === "POST" && path === "/api/save") {
      try {
        const { username, password, appData } = await request.json();

        const user = await authenticate(username, password);
        if (!user) {
          return new Response(JSON.stringify({ error: "Não autorizado." }), { status: 401 });
        }

        user.data = appData;

        await env.DB.put(`user:${username}`, JSON.stringify(user));

        return new Response(JSON.stringify({ success: true }));
      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro ao salvar." }), { status: 500 });
      }
    }

    // =====================================================================
    // 👷 FUNCIONÁRIOS
    // =====================================================================

    if (request.method === "POST" && path === "/api/funcionario") {
      try {
        const { username, password, funcionario } = await request.json();

        const user = await authenticate(username, password);
        if (!user) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401 });

        if (!funcionario?.cpf || !funcionario?.nome) {
          return new Response(JSON.stringify({ error: "Dados inválidos" }), { status: 400 });
        }

        const key = `funcionario:${funcionario.cpf}`;
        const existing = await env.DB.get(key);

        if (existing) {
          return new Response(JSON.stringify({ error: "Funcionário já existe" }), { status: 400 });
        }

        await env.DB.put(key, JSON.stringify({
          ...funcionario,
          criado_em: Date.now()
        }));

        return new Response(JSON.stringify({ success: true }));

      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro ao criar funcionário" }), { status: 500 });
      }
    }

    if (request.method === "GET" && path === "/api/funcionarios") {
      const list = await env.DB.list({ prefix: "funcionario:" });

      const items = await Promise.all(
        list.keys.map(k => env.DB.get(k.name))
      );

      return new Response(JSON.stringify(items.map(JSON.parse)));
    }

    // =====================================================================
    // 🏗️ OBRAS
    // =====================================================================

    if (request.method === "POST" && path === "/api/obra") {
      try {
        const { username, password, obra } = await request.json();

        const user = await authenticate(username, password);
        if (!user) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401 });

        if (!obra?.id || !obra?.nome || !obra?.engenheiro) {
          return new Response(JSON.stringify({ error: "Código, nome e engenheiro são obrigatórios." }), { status: 400 });
        }

        const id = obra.id.trim().toUpperCase();
        const key = `obra:${id}`;

        const existing = await env.DB.get(key);
        if (existing) {
          return new Response(JSON.stringify({ error: "Obra já existe." }), { status: 400 });
        }

        await env.DB.put(key, JSON.stringify({
          ...obra,
          id,
          criado_em: Date.now()
        }));

        return new Response(JSON.stringify({ success: true }));

      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro ao criar obra" }), { status: 500 });
      }
    }

    if (request.method === "GET" && path === "/api/obras") {
      const list = await env.DB.list({ prefix: "obra:" });

      const items = await Promise.all(
        list.keys.map(k => env.DB.get(k.name))
      );

      return new Response(JSON.stringify(items.map(JSON.parse)));
    }

    return new Response("Not Found", { status: 404 });
  },
};