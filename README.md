# Регистрация САТУРН РП (Netlify)

1. Залить папку в GitHub-репозиторий → Netlify → Add new site → Import from Git
   (или `netlify deploy --prod` через CLI). Build command не нужен.
2. Site settings → Environment variables: заполнить всё из `.env.example`.
3. На хостинге MySQL разрешить внешние подключения (Remote MySQL) для вашего пользователя.
4. Подтверждение e-mail использует таблицу `pending_reg` — создаётся автоматически.
5. Проверить `HASH_MODE` (см. netlify/functions/_hash.js) — должен совпадать с модом.
6. Ссылку на APK задать в DOWNLOAD_URL; не класть APK в public/ — иначе его можно скачать по прямому адресу раньше даты.
