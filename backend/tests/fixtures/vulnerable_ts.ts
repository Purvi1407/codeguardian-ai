/**
 * Small TypeScript-specific fixture. The rule logic itself is shared
 * with JS (see vulnerable_js.js / safe_js.js for full rule coverage) —
 * this file exists to confirm the TS grammar path (type annotations,
 * interfaces, access modifiers) parses correctly and that detection
 * still works through TS-specific syntax the plain JS grammar doesn't
 * have.
 */
interface UserQuery {
  id: string;
}

function sql_injection_string_build__typed_param(id: string): void {
  db.query(`SELECT * FROM users WHERE id = ${id}`);
}

function safe_sql_typed_param(id: string): void {
  db.query("SELECT * FROM users WHERE id = ?", [id]);
}

class TypedService {
  private secret: string = "";

  weak_crypto_hash__typed_method(): void {
    crypto.createHash('sha1');
  }

  safe_typed_method(): void {
    crypto.createHash('sha256');
  }
}
