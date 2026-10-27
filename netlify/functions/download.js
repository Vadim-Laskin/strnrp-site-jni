// Отдаёт ссылку на игру только начиная с RELEASE_DATE (сравнивается только дата, МСК).
const RELEASE_DATE = '2026-10-30';

const todayMsk = () =>
  new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Moscow', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());

exports.handler = async () => {
  const today = todayMsk();
  if (today < RELEASE_DATE) {
    return {
      statusCode: 403,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
      body: 'Скачивание станет доступно 30 октября 2026 года.',
    };
  }
  const url = process.env.DOWNLOAD_URL;
  if (!url) return { statusCode: 500, body: 'DOWNLOAD_URL не задан' };
  return { statusCode: 302, headers: { Location: url, 'Cache-Control': 'no-store' }, body: '' };
};
