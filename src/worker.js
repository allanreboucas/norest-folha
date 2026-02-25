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

    // =====================================================================
    // 👷 FUNCIONÁRIOS
    // =====================================================================

    if (request.method === "POST" && path === "/api/funcionario") {
      try {
        const { username, password, funcionario } = await request.json();

        const user = await authenticate(username, password);
        if (!user) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401 });

        if (!funcionario?.cpf || !funcionario?.nome || !funcionario?.funcao || !funcionario?.diaria) {
          return new Response(JSON.stringify({ error: "CPF, nome, função e diária são obrigatórios." }), { status: 400 });
        }

        const cpf = funcionario.cpf.replace(/\D/g, '');
        if (cpf.length !== 11) {
          return new Response(JSON.stringify({ error: "CPF inválido." }), { status: 400 });
        }

        const key = `funcionario:${cpf}`;
        const existing = await env.DB.get(key);
        if (existing) {
          return new Response(JSON.stringify({ error: "Funcionário já existe." }), { status: 400 });
        }

        await env.DB.put(key, JSON.stringify({
          cpf,
          nome: funcionario.nome.trim().toUpperCase(),
          funcao: funcionario.funcao.trim().toUpperCase(),
          diaria: parseFloat(funcionario.diaria),
          criado_em: Date.now()
        }));

        return new Response(JSON.stringify({ success: true }));

      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro ao criar funcionário." }), { status: 500 });
      }
    }

    if (request.method === "GET" && path === "/api/funcionarios") {
      const list = await env.DB.list({ prefix: "funcionario:" });
      const items = await Promise.all(list.keys.map(k => env.DB.get(k.name)));
      return new Response(JSON.stringify(items.map(JSON.parse)));
    }

    if (request.method === "PUT" && path.startsWith("/api/funcionario/")) {
      try {
        const { username, password, funcionario } = await request.json();

        const user = await authenticate(username, password);
        if (!user) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401 });

        const cpf = decodeURIComponent(path.split("/api/funcionario/")[1]);
        const key = `funcionario:${cpf}`;

        const existing = await env.DB.get(key);
        if (!existing) return new Response(JSON.stringify({ error: "Funcionário não encontrado." }), { status: 404 });

        if (!funcionario?.nome || !funcionario?.funcao || !funcionario?.diaria) {
          return new Response(JSON.stringify({ error: "Nome, função e diária são obrigatórios." }), { status: 400 });
        }

        const current = JSON.parse(existing);
        await env.DB.put(key, JSON.stringify({
          ...current,
          nome: funcionario.nome.trim().toUpperCase(),
          funcao: funcionario.funcao.trim().toUpperCase(),
          diaria: parseFloat(funcionario.diaria)
        }));

        return new Response(JSON.stringify({ success: true }));
      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro ao editar funcionário." }), { status: 500 });
      }
    }

    if (request.method === "DELETE" && path.startsWith("/api/funcionario/")) {
      try {
        const { username, password } = await request.json();

        const user = await authenticate(username, password);
        if (!user) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401 });

        const cpf = decodeURIComponent(path.split("/api/funcionario/")[1]);
        const key = `funcionario:${cpf}`;

        const existing = await env.DB.get(key);
        if (!existing) return new Response(JSON.stringify({ error: "Funcionário não encontrado." }), { status: 404 });

        await env.DB.delete(key);

        return new Response(JSON.stringify({ success: true }));
      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro ao excluir funcionário." }), { status: 500 });
      }
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

    if (request.method === "PUT" && path.startsWith("/api/obra/")) {
      try {
        const { username, password, obra } = await request.json();

        const user = await authenticate(username, password);
        if (!user) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401 });

        const id = decodeURIComponent(path.split("/api/obra/")[1]).toUpperCase();
        const key = `obra:${id}`;

        const existing = await env.DB.get(key);
        if (!existing) return new Response(JSON.stringify({ error: "Obra não encontrada." }), { status: 404 });

        if (!obra?.nome || !obra?.engenheiro) {
          return new Response(JSON.stringify({ error: "Nome e engenheiro são obrigatórios." }), { status: 400 });
        }

        const current = JSON.parse(existing);
        const updated = { ...current, nome: obra.nome.trim(), engenheiro: obra.engenheiro.trim() };
        if (obra.periodos) updated.periodos = obra.periodos;
        await env.DB.put(key, JSON.stringify(updated));

        return new Response(JSON.stringify({ success: true }));
      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro ao editar obra." }), { status: 500 });
      }
    }

    if (request.method === "DELETE" && path.startsWith("/api/obra/")) {
      try {
        const { username, password } = await request.json();

        const user = await authenticate(username, password);
        if (!user) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401 });

        const id = decodeURIComponent(path.split("/api/obra/")[1]).toUpperCase();
        const key = `obra:${id}`;

        const existing = await env.DB.get(key);
        if (!existing) return new Response(JSON.stringify({ error: "Obra não encontrada." }), { status: 404 });

        await env.DB.delete(key);

        return new Response(JSON.stringify({ success: true }));
      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro ao excluir obra." }), { status: 500 });
      }
    }

    // =====================================================================
    // 📋 FOLHA DE FREQUÊNCIA
    // =====================================================================

    if (request.method === "GET" && path === "/api/folha") {
      const obra = url.searchParams.get("obra");
      const semana = url.searchParams.get("semana");
      if (!obra || !semana) return new Response(JSON.stringify({ error: "Parâmetros obrigatórios." }), { status: 400 });
      const data = await env.DB.get(`folha:${obra}:${semana}`);
      if (!data) return new Response(JSON.stringify({ registros: [] }));
      return new Response(data, { headers: { "Content-Type": "application/json" } });
    }

    if (request.method === "POST" && path === "/api/folha") {
      try {
        const { username, password, obra, semana, registros } = await request.json();
        const user = await authenticate(username, password);
        if (!user) return new Response(JSON.stringify({ error: "Não autorizado" }), { status: 401 });
        if (!obra || !semana || !Array.isArray(registros)) {
          return new Response(JSON.stringify({ error: "Dados inválidos." }), { status: 400 });
        }
        await env.DB.put(`folha:${obra}:${semana}`, JSON.stringify({ obra, semana, registros, atualizado_em: Date.now() }));
        return new Response(JSON.stringify({ success: true }));
      } catch (err) {
        return new Response(JSON.stringify({ error: "Erro ao salvar folha." }), { status: 500 });
      }
    }

    if (request.method === "GET" && path === "/api/folhas") {
      const semana = url.searchParams.get("semana");
      if (!semana) return new Response(JSON.stringify({ error: "Parâmetro 'semana' obrigatório." }), { status: 400 });
      const list = await env.DB.list({ prefix: "folha:" });
      const matchingKeys = list.keys.filter(k => k.name.endsWith(`:${semana}`));
      if (!matchingKeys.length) return new Response(JSON.stringify([]));
      const items = await Promise.all(matchingKeys.map(k => env.DB.get(k.name)));
      return new Response(JSON.stringify(items.filter(Boolean).map(JSON.parse)));
    }

    return new Response("Not Found", { status: 404 });
  },
};