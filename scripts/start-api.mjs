import {readFile,readdir} from "node:fs/promises";
import {createHash} from "node:crypto";
import {join} from "node:path";
import {spawn} from "node:child_process";
import pg from "pg";
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL});
async function migrate(){
 const client=await pool.connect();
 try{
  await client.query("SELECT pg_advisory_lock(72194261)");
  // Existing named volumes do not rerun /docker-entrypoint-initdb.d.
  // All schema DDL is idempotent; never drop the database or its volume.
  await client.query(await readFile("database/schema.sql","utf8"));
  await client.query("CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY,applied_at timestamptz DEFAULT now(),checksum text NOT NULL)");
  const files=(await readdir("database/migrations")).filter(f=>/^\\d{4}_[a-z0-9_]+\\.sql$/.test(f)).sort();
  for(const filename of files){
   const version=filename.slice(0,-4);
   const sql=await readFile(join("database/migrations",filename),"utf8");
   const checksum=createHash("sha256").update(sql).digest("hex");
   const old=await client.query("SELECT checksum FROM schema_migrations WHERE version=$1",[version]);
   if(old.rowCount){
    if(old.rows[0].checksum!==checksum)throw Error("Migration checksum mismatch: "+version);
    continue;
   }
   await client.query("BEGIN");
   try{
    await client.query(sql);
    await client.query("INSERT INTO schema_migrations(version,checksum) VALUES($1,$2)",[version,checksum]);
    await client.query("COMMIT");
    console.info("Applied migration",version);
   }catch(error){await client.query("ROLLBACK");throw error}
  }
 }finally{
  try{await client.query("SELECT pg_advisory_unlock(72194261)")}finally{client.release()}
 }
}
try{
 await migrate();await pool.end();
 const child=spawn(process.execPath,["node_modules/tsx/dist/cli.mjs","apps/api/src/index.ts"],{stdio:"inherit",env:process.env});
 for(const signal of ["SIGINT","SIGTERM"])process.on(signal,()=>child.kill(signal));
 child.on("exit",(code,signal)=>process.exit(code??(signal?1:0)));
}catch(error){console.error("Nexora database migration failed:",error);await pool.end();process.exit(1)}
