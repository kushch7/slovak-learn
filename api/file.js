import fs from "node:fs/promises";
import path from "node:path";
import { verifyFileToken, findAccount, teacherConfig } from "./app.js";

/* Захищена видача PDF-матеріалів.
   Учень: шпаргалка й домашнє завдання лише відкритих йому уроків + довідник для учнів.
   Лектор: усе (презентації, тести з ключами, довідники). */
const DIR = path.join(process.cwd(), "api", "_files");

function page(res, code, msg) {
  res.statusCode = code;
  res.setHeader("content-type", "text/html; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Slovak Learn</title><body style="font-family:system-ui,sans-serif;background:#F3F6FC;color:#0F3271;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px"><div style="max-width:420px;background:#fff;border-top:6px solid #FFD25A;padding:24px"><b style="font-size:18px">Slovak Learn</b><p>${msg}</p></div>`);
}

export default async function handler(req, res) {
  try {
    const url = new URL(req.url, "http://x");
    const f = String(url.searchParams.get("f") || "");
    const tok = verifyFileToken(url.searchParams.get("t"));
    if (!/^[a-z0-9-]{2,40}$/.test(f)) return page(res, 404, "Файл не знайдено.");
    if (!tok) return page(res, 401, "Посилання застаріло. Оновіть сторінку платформи й відкрийте матеріал ще раз.");

    let ok = false;
    if (tok.r === "t") {
      const cfg = await teacherConfig();
      ok = (cfg.v || 1) === tok.pv;
    } else if (tok.r === "s") {
      const acc = await findAccount(tok.id);
      if (acc && (acc.pv || 1) === tok.pv) {
        const m = f.match(/^l(\d{1,2})-(tahak|domaca-uloha)$/);
        const hidden = (acc.hide || []).map(Number);
        // modules have 6 lessons each (1–6 → 1, 7–12 → 2, …)
        ok = f === "prirucka-student" || (!!m && (acc.unlocked || [1]).map(Number).includes(+m[1]) && !hidden.includes(Math.ceil(+m[1] / 6)) && !(acc.mclose || []).includes((m[2] === "tahak" ? "c" : "h") + (+m[1])));
      }
    }
    if (!ok) return page(res, 403, "Цей матеріал вам ще недоступний. Його відкриє лектор після заняття.");

    let buf;
    try { buf = await fs.readFile(path.join(DIR, f + ".pdf")); } catch { return page(res, 404, "Файл не знайдено."); }
    res.statusCode = 200;
    res.setHeader("content-type", "application/pdf");
    res.setHeader("content-disposition", `inline; filename="${f}.pdf"`);
    res.setHeader("cache-control", "private, no-store");
    res.setHeader("x-robots-tag", "noindex, nofollow");
    res.end(buf);
  } catch (e) {
    return page(res, 500, "Помилка сервера. Спробуйте пізніше.");
  }
}
