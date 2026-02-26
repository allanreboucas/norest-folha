import html from './index.html';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

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
    // 🔑 PAGINAÇÃO KV — lista todas as chaves sem limite de 1000 (C4)
    // =====================================================================
    async function listAll(prefix) {
      const keys = [];
      let cursor;
      do {
        const r = await env.DB.list({ prefix, cursor, limit: 1000 });
        keys.push(...r.keys);
        cursor = r.list_complete ? null : r.cursor;
      } while (cursor);
      return keys;
    }

    // =====================================================================
    // 🔐 AUTENTICAÇÃO POR TOKEN DE SESSÃO (C1)
    // =====================================================================
    async function authenticate() {
      const authHeader = request.headers.get('Authorization') || '';
      if (!authHeader.startsWith('Bearer ')) return null;
      const token = authHeader.slice(7);
      if (!token) return null;
      const raw = await env.DB.get(`session:${token}`);
      if (!raw) return null;
      const session = JSON.parse(raw);
      // R2: Renovar TTL da sessão a cada requisição autenticada (sliding window 8h)
      await env.DB.put(`session:${token}`, raw, { expirationTtl: 28800 });
      return session;
    }

    // =====================================================================
    // 📋 VALIDAÇÃO MATEMÁTICA DE CPF (M4, R4)
    // =====================================================================
    function validarCPF(cpf) {
      cpf = cpf.replace(/\D/g, '');
      if (cpf.length !== 11 || /^(\d)\1{10}$/.test(cpf)) return false;
      let s = 0, r;
      for (let i = 1; i <= 9; i++) s += +cpf[i - 1] * (11 - i);
      r = (s * 10) % 11; if (r >= 10) r = 0;
      if (r !== +cpf[9]) return false;
      s = 0;
      for (let i = 1; i <= 10; i++) s += +cpf[i - 1] * (12 - i);
      r = (s * 10) % 11; if (r >= 10) r = 0;
      return r === +cpf[10];
    }

    // Helper para respostas JSON com headers de segurança (I6)
    function jsonResponse(data, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: {
          'Content-Type': 'application/json',
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'Referrer-Policy': 'no-referrer',
        }
      });
    }

    // --- ROTA: FRONTEND ---
    if (method === "GET" && path === "/") {
      return new Response(html, {
        headers: {
          "Content-Type": "text/html;charset=UTF-8",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY",
          "Referrer-Policy": "no-referrer",
          "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
          "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
          "Content-Security-Policy": [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
            "font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com",
            "img-src * data: blob:",
            "frame-src https://drive.google.com https://1drv.ms https://onedrive.live.com https://www.dropbox.com",
            "connect-src 'self' https://cdnjs.cloudflare.com"
          ].join('; ')
        },
      });
    }

    // --- ROTA: REGISTER ---
    if (method === "POST" && path === "/api/register") {
      try {
        const { username, password, token } = await request.json();

        if (!username || !password || !token) {
          return jsonResponse({ error: "Dados incompletos." }, 400);
        }

        if (token !== env.REGISTRATION_TOKEN) {
          return jsonResponse({ error: "Token inválido." }, 403);
        }

        const existing = await env.DB.get(`user:${username}`);
        if (existing) {
          return jsonResponse({ error: "Usuário já existe." }, 400);
        }

        const hashedPassword = await hashPassword(password);
        await env.DB.put(`user:${username}`, JSON.stringify({ password: hashedPassword, data: {} }));

        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Erro no registro." }, 500);
      }
    }

    // --- ROTA: LOGIN ---
    if (method === "POST" && path === "/api/login") {
      try {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const blockKey = `block:${ip}`;

        const attemptsRaw = await env.DB.get(blockKey);
        const attempts = attemptsRaw ? parseInt(attemptsRaw) : 0;

        if (attempts >= 5) {
          return jsonResponse({ error: "Bloqueado por excesso de tentativas." }, 429);
        }

        const { username, password } = await request.json();

        async function registerFailure() {
          await env.DB.put(blockKey, (attempts + 1).toString(), { expirationTtl: 900 });
        }

        const userRaw = await env.DB.get(`user:${username}`);
        if (!userRaw) {
          await registerFailure();
          return jsonResponse({ error: "Credenciais inválidas." }, 401);
        }

        const user = JSON.parse(userRaw);
        const inputHash = await hashPassword(password);

        if (user.password !== inputHash) {
          await registerFailure();
          return jsonResponse({ error: "Credenciais inválidas." }, 401);
        }

        await env.DB.delete(blockKey);

        // Gera token de sessão com TTL de 8 horas (C1, D8)
        const token = crypto.randomUUID();
        await env.DB.put(`session:${token}`, JSON.stringify({ username }), { expirationTtl: 28800 });

        return jsonResponse({ success: true, token });

      } catch (err) {
        return jsonResponse({ error: "Erro no login." }, 500);
      }
    }

    // --- ROTA: LOGOUT (C1, D8) ---
    if (method === "POST" && path === "/api/logout") {
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
      if (token) await env.DB.delete(`session:${token}`);
      return jsonResponse({ success: true });
    }

    // --- ROTA: ME — valida sessão (C1) ---
    if (method === "GET" && path === "/api/me") {
      const session = await authenticate();
      if (!session) return jsonResponse({ error: "Sessão inválida." }, 401);
      return jsonResponse({ username: session.username });
    }

    // =====================================================================
    // 👷 FUNCIONÁRIOS
    // =====================================================================

    if (method === "POST" && path === "/api/funcionario") {
      try {
        const { funcionario } = await request.json();

        const session = await authenticate();
        if (!session) return jsonResponse({ error: "Não autorizado" }, 401);

        if (!funcionario?.cpf || !funcionario?.nome || !funcionario?.funcao || !funcionario?.diaria) {
          return jsonResponse({ error: "CPF, nome, função e diária são obrigatórios." }, 400);
        }

        const cpf = funcionario.cpf.replace(/\D/g, '');
        if (!validarCPF(cpf)) {
          return jsonResponse({ error: "CPF inválido." }, 400);
        }

        // M4: Validar diária positiva
        const diaria = parseFloat(funcionario.diaria);
        if (isNaN(diaria) || diaria <= 0) {
          return jsonResponse({ error: "Diária deve ser um valor positivo." }, 400);
        }

        const key = `funcionario:${cpf}`;
        const existing = await env.DB.get(key);
        if (existing) {
          return jsonResponse({ error: "Funcionário já existe." }, 400);
        }

        await env.DB.put(key, JSON.stringify({
          cpf,
          nome: funcionario.nome.trim().toUpperCase(),
          funcao: funcionario.funcao.trim().toUpperCase(),
          diaria: parseFloat(funcionario.diaria),
          criado_em: Date.now()
        }));

        return jsonResponse({ success: true });

      } catch (err) {
        return jsonResponse({ error: "Erro ao criar funcionário." }, 500);
      }
    }

    if (method === "GET" && path === "/api/funcionarios") {
      const session = await authenticate();
      if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
      const keys = await listAll("funcionario:");
      // R5: limitar a 500 registros por segurança de performance
      const limited = keys.slice(0, 500);
      const items = await Promise.all(limited.map(k => env.DB.get(k.name)));
      return jsonResponse(items.filter(Boolean).map(JSON.parse));
    }

    if (method === "PUT" && path.startsWith("/api/funcionario/")) {
      try {
        const { funcionario } = await request.json();

        const session = await authenticate();
        if (!session) return jsonResponse({ error: "Não autorizado" }, 401);

        const cpf = decodeURIComponent(path.split("/api/funcionario/")[1]);
        const key = `funcionario:${cpf}`;

        const existing = await env.DB.get(key);
        if (!existing) return jsonResponse({ error: "Funcionário não encontrado." }, 404);

        if (!funcionario?.nome || !funcionario?.funcao || !funcionario?.diaria) {
          return jsonResponse({ error: "Nome, função e diária são obrigatórios." }, 400);
        }

        // M4: Validar diária positiva no PUT também
        const diariaEdit = parseFloat(funcionario.diaria);
        if (isNaN(diariaEdit) || diariaEdit <= 0) {
          return jsonResponse({ error: "Diária deve ser um valor positivo." }, 400);
        }

        const current = JSON.parse(existing);
        await env.DB.put(key, JSON.stringify({
          ...current,
          nome: funcionario.nome.trim().toUpperCase(),
          funcao: funcionario.funcao.trim().toUpperCase(),
          diaria: diariaEdit,
          modificado_por: session.username,
          modificado_em: Date.now()
        }));

        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Erro ao editar funcionário." }, 500);
      }
    }

    if (method === "DELETE" && path.startsWith("/api/funcionario/")) {
      try {
        const session = await authenticate();
        if (!session) return jsonResponse({ error: "Não autorizado" }, 401);

        const cpf = decodeURIComponent(path.split("/api/funcionario/")[1]);
        const key = `funcionario:${cpf}`;

        const existing = await env.DB.get(key);
        if (!existing) return jsonResponse({ error: "Funcionário não encontrado." }, 404);

        await env.DB.delete(key);

        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Erro ao excluir funcionário." }, 500);
      }
    }

    // =====================================================================
    // 🏗️ OBRAS
    // =====================================================================

    if (method === "POST" && path === "/api/obra") {
      try {
        const { obra } = await request.json();

        const session = await authenticate();
        if (!session) return jsonResponse({ error: "Não autorizado" }, 401);

        if (!obra?.id || !obra?.nome || !obra?.engenheiro) {
          return jsonResponse({ error: "Código, nome e engenheiro são obrigatórios." }, 400);
        }

        const id = obra.id.trim().toUpperCase();
        const key = `obra:${id}`;

        const existing = await env.DB.get(key);
        if (existing) {
          return jsonResponse({ error: "Obra já existe." }, 400);
        }

        await env.DB.put(key, JSON.stringify({
          ...obra,
          id,
          criado_em: Date.now()
        }));

        return jsonResponse({ success: true });

      } catch (err) {
        return jsonResponse({ error: "Erro ao criar obra" }, 500);
      }
    }

    if (method === "GET" && path === "/api/obras") {
      const session = await authenticate();
      if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
      const keys = await listAll("obra:");
      const items = await Promise.all(keys.map(k => env.DB.get(k.name)));
      return jsonResponse(items.filter(Boolean).map(JSON.parse));
    }

    if (method === "PUT" && path.startsWith("/api/obra/")) {
      try {
        const { obra } = await request.json();

        const session = await authenticate();
        if (!session) return jsonResponse({ error: "Não autorizado" }, 401);

        const id = decodeURIComponent(path.split("/api/obra/")[1]).toUpperCase();
        const key = `obra:${id}`;

        const existing = await env.DB.get(key);
        if (!existing) return jsonResponse({ error: "Obra não encontrada." }, 404);

        if (!obra?.nome || !obra?.engenheiro) {
          return jsonResponse({ error: "Nome e engenheiro são obrigatórios." }, 400);
        }

        const current = JSON.parse(existing);
        const updated = {
          ...current,
          nome: obra.nome.trim(),
          engenheiro: obra.engenheiro.trim(),
          orcamento:    obra.orcamento    !== undefined ? obra.orcamento    : (current.orcamento    ?? null),
          data_inicio:  obra.data_inicio  !== undefined ? obra.data_inicio  : (current.data_inicio  ?? null),
          data_termino: obra.data_termino !== undefined ? obra.data_termino : (current.data_termino ?? null),
          progresso:    obra.progresso    !== undefined ? obra.progresso    : (current.progresso    ?? 0),
          status:       obra.status       || current.status || 'em_andamento',
          modificado_por: session.username,
          modificado_em: Date.now()
        };
        if (obra.periodos) updated.periodos = obra.periodos;
        await env.DB.put(key, JSON.stringify(updated));

        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Erro ao editar obra." }, 500);
      }
    }

    if (method === "DELETE" && path.startsWith("/api/obra/")) {
      try {
        const session = await authenticate();
        if (!session) return jsonResponse({ error: "Não autorizado" }, 401);

        const id = decodeURIComponent(path.split("/api/obra/")[1]).toUpperCase();
        const key = `obra:${id}`;

        const existing = await env.DB.get(key);
        if (!existing) return jsonResponse({ error: "Obra não encontrada." }, 404);

        // Cascade delete: remove folhas, adicionais e fotos associadas (C3)
        const [fl, ad, fo] = await Promise.all([
          listAll(`folha:${id}:`),
          listAll(`adicionais:${id}:`),
          listAll(`fotos:${id}:`)
        ]);
        await Promise.all([
          env.DB.delete(key),
          ...[...fl, ...ad, ...fo].map(k => env.DB.delete(k.name))
        ]);

        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Erro ao excluir obra." }, 500);
      }
    }

    // =====================================================================
    // 📋 FOLHA DE FREQUÊNCIA
    // =====================================================================

    if (method === "GET" && path === "/api/folha") {
      const session = await authenticate();
      if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
      const obra = url.searchParams.get("obra");
      const semana = url.searchParams.get("semana");
      if (!obra || !semana) return jsonResponse({ error: "Parâmetros obrigatórios." }, 400);
      const data = await env.DB.get(`folha:${obra}:${semana}`);
      if (!data) return jsonResponse({ registros: [] });
      return new Response(data, { headers: { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff' } });
    }

    if (method === "POST" && path === "/api/folha") {
      try {
        const { obra, semana, registros } = await request.json();
        const session = await authenticate();
        if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
        if (!obra || !semana || !Array.isArray(registros)) {
          return jsonResponse({ error: "Dados inválidos." }, 400);
        }
        await env.DB.put(`folha:${obra}:${semana}`, JSON.stringify({
          obra, semana, registros,
          modificado_por: session.username,
          atualizado_em: Date.now()
        }));
        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Erro ao salvar folha." }, 500);
      }
    }

    if (method === "GET" && path === "/api/folhas") {
      const session = await authenticate();
      if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
      const semana = url.searchParams.get("semana");
      if (!semana) return jsonResponse({ error: "Parâmetro 'semana' obrigatório." }, 400);
      const keys = await listAll("folha:");
      const matchingKeys = keys.filter(k => k.name.endsWith(`:${semana}`));
      if (!matchingKeys.length) return jsonResponse([]);
      const items = await Promise.all(matchingKeys.map(k => env.DB.get(k.name)));
      return jsonResponse(items.filter(Boolean).map(JSON.parse));
    }

    // =====================================================================
    // 📊 CUSTO ACUMULADO POR OBRA (para Dashboard)
    // =====================================================================

    if (method === "GET" && path === "/api/custo-obras") {
      const session = await authenticate();
      if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
      const dias = ['dom','seg','ter','qua','qui','sex','sab'];
      const [folhaKeys, adicionaisKeys] = await Promise.all([
        listAll("folha:"),
        listAll("adicionais:")
      ]);
      const [folhaItems, adicionaisItems] = await Promise.all([
        Promise.all(folhaKeys.map(k => env.DB.get(k.name))),
        Promise.all(adicionaisKeys.map(k => env.DB.get(k.name)))
      ]);
      const custoPorObra = {};
      folhaItems.filter(Boolean).map(JSON.parse).forEach(folha => {
        if (!folha.obra || !Array.isArray(folha.registros)) return;
        let total = 0;
        folha.registros.forEach(reg => {
          let somaDias = 0;
          dias.forEach(d => {
            const v = reg.freq?.[d];
            if (v === 'full') somaDias += 1;
            else if (v === 'half') somaDias += 0.5;
          });
          total += somaDias * (reg.diaria_historica || 0) + (reg.horas_extras || 0) * (reg.valor_hora_extra || 0);
        });
        custoPorObra[folha.obra] = (custoPorObra[folha.obra] || 0) + total;
      });
      adicionaisItems.filter(Boolean).map(JSON.parse).forEach(ad => {
        if (!ad.obra || !Array.isArray(ad.itens)) return;
        const totalAd = ad.itens.reduce((s, i) => s + (parseFloat(i.valor) || 0), 0);
        custoPorObra[ad.obra] = (custoPorObra[ad.obra] || 0) + totalAd;
      });
      return jsonResponse(custoPorObra);
    }

    // =====================================================================
    // 💰 ADICIONAIS FINANCEIROS POR OBRA
    // =====================================================================

    if (method === "GET" && path === "/api/adicionais") {
      const session = await authenticate();
      if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
      const obra = url.searchParams.get("obra");
      const semana = url.searchParams.get("semana");
      if (!obra || !semana) return jsonResponse({ error: "Parâmetros obrigatórios." }, 400);
      const data = await env.DB.get(`adicionais:${obra}:${semana}`);
      if (!data) return jsonResponse({ itens: [] });
      return new Response(data, { headers: { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff' } });
    }

    if (method === "POST" && path === "/api/adicionais") {
      try {
        const { obra, semana, itens } = await request.json();
        const session = await authenticate();
        if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
        if (!obra || !semana || !Array.isArray(itens)) {
          return jsonResponse({ error: "Dados inválidos." }, 400);
        }
        await env.DB.put(`adicionais:${obra}:${semana}`, JSON.stringify({
          obra, semana, itens,
          modificado_por: session.username,
          atualizado_em: Date.now()
        }));
        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Erro ao salvar adicionais." }, 500);
      }
    }

    // =====================================================================
    // 📸 FOTOS DA SEMANA
    // =====================================================================

    if (method === "GET" && path === "/api/fotos") {
      const session = await authenticate();
      if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
      const obra = url.searchParams.get("obra");
      const semana = url.searchParams.get("semana");
      if (!obra || !semana) return jsonResponse({ error: "Parâmetros obrigatórios." }, 400);
      const data = await env.DB.get(`fotos:${obra}:${semana}`);
      if (!data) return jsonResponse({ fotos: { dom: null, seg: null, ter: null, qua: null, qui: null, sex: null, sab: null } });
      return new Response(data, { headers: { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff' } });
    }

    if (method === "POST" && path === "/api/fotos") {
      try {
        const { obra, semana, fotos } = await request.json();
        const session = await authenticate();
        if (!session) return jsonResponse({ error: "Não autorizado" }, 401);
        if (!obra || !semana || typeof fotos !== 'object') {
          return jsonResponse({ error: "Dados inválidos." }, 400);
        }
        await env.DB.put(`fotos:${obra}:${semana}`, JSON.stringify({ obra, semana, fotos, atualizado_em: Date.now() }));
        return jsonResponse({ success: true });
      } catch (err) {
        return jsonResponse({ error: "Erro ao salvar fotos." }, 500);
      }
    }

    return new Response("Not Found", { status: 404 });
  },
};
