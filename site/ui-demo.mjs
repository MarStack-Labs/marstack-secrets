const playwright = await import(process.env.PLAYWRIGHT_MODULE ?? 'playwright')
const { chromium } = playwright.chromium ? playwright : playwright.default

const BASE = process.env.BASE ?? 'http://127.0.0.1:18400'
const BOOTSTRAP = process.env.BOOTSTRAP
const OUT = process.env.VIDEO_DIR ?? '/tmp/marsec-ui/video'
const WIDTH = Number(process.env.WIDTH ?? 1280)
const HEIGHT = Number(process.env.HEIGHT ?? 860)
const THRESHOLD = Number(process.env.THRESHOLD ?? 3)
const SIGNAL_DIR = process.env.SIGNAL_DIR

if (!BOOTSTRAP) {
  console.error('BOOTSTRAP is not set')
  process.exit(1)
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms))

const browser = await chromium.launch()
const context = await browser.newContext({
  viewport: { width: WIDTH, height: HEIGHT },
  deviceScaleFactor: 2,
  recordVideo: { dir: OUT, size: { width: WIDTH, height: HEIGHT } },
})
const page = await context.newPage()

await page.goto(`${BASE}/ui/`, { waitUntil: 'networkidle' })
await wait(2000)

await page.fill('#init-shares', '5')
await page.fill('#init-threshold', String(THRESHOLD))
await wait(600)
await page.click('#do-init')
await page.waitForSelector('#init-shares-out', { state: 'visible', timeout: 15000 })
await wait(2400)

const shares = await page.$eval('#init-shares-out', (el) =>
  el.innerText.split('\n').map((s) => s.trim()).filter(Boolean),
)

console.log(`state after initialising: ${await page.textContent('#fact-state')}`)

if (SIGNAL_DIR) {
  const { writeFileSync, existsSync, rmSync } = await import('node:fs')
  const { join } = await import('node:path')
  const done = join(SIGNAL_DIR, 'restart-done')
  rmSync(done, { force: true })
  writeFileSync(join(SIGNAL_DIR, 'restart-please'), '')
  for (let i = 0; i < 300 && !existsSync(done); i++) await wait(100)
  if (!existsSync(done)) {
    console.error('the restart never completed')
    process.exit(1)
  }
  await page.reload({ waitUntil: 'networkidle' })
  await wait(2400)
}

console.log(`state after restarting: ${await page.textContent('#fact-state')}`)

await page.waitForSelector('#unseal-panel', { state: 'visible', timeout: 15000 })
for (const share of shares.slice(0, THRESHOLD)) {
  await page.fill('#unseal-share', share)
  await wait(500)
  await page.click('#do-unseal')
  await wait(1500)
}
await wait(1800)

await page.fill('#login-bootstrap', BOOTSTRAP)
await wait(600)
await page.click('#do-login')
await wait(2000)

await page.click('[data-view="secrets"]')
await wait(1200)
await page.fill('#secret-tenant', 'prod')
await page.fill('#secret-path', 'payment-api')
await wait(600)
await page.fill('#secret-new', 'hunter2-the-real-one')
await wait(600)
await page.click('#secret-write')
await wait(1800)
await page.click('#secret-read')
await wait(1800)
await page.click('#secret-reveal')
await wait(2400)

for (const view of ['params', 'leases', 'access']) {
  await page.click(`[data-view="${view}"]`)
  await wait(2200)
}

await context.close()
await browser.close()
console.log('recorded')
