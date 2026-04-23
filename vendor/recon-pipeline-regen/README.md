# Regenerar `server/recon-pipeline.js`

O script `node server/scripts/build-recon-pipeline.mjs` extrai blocos de código a partir do ficheiro **congelado** nesta pasta:

- `ghostrecon-server-index.js` — cópia de referência do antigo `server/index.js` do projeto recon (antes de removeres o subfolder `GHOSTRECON/`).

**Quando actualizar:** se precisares de re-sincronizar o recon com uma versão mais nova do servidor recon, substitui `ghostrecon-server-index.js` por uma cópia actualizada e volta a correr o script de build. O `recon-pipeline.js` no GHOSTCTF continua a ser o artefacto gerado; podes também editá-lo manualmente.
