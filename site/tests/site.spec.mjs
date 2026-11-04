import { test, expect } from '@playwright/test';

test('home, installation, navigation and assets work under /gomap/', async ({ page }, info) => {
  const errors = [];
  page.on('pageerror', err => errors.push(err.message));
  await page.goto('');
  await expect(page.getByRole('heading', { name: 'GoMap', exact: true })).toBeVisible();
  const terminal = page.locator('img[src="/gomap/terminal.png"]');
  await expect(terminal).toBeVisible();
  expect(await terminal.evaluate(img => img.complete && img.naturalWidth > 0)).toBeTruthy();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: test.info().outputPath(`${info.project.name}-home.png`), fullPage: true });
  await page.getByRole('link', { name: 'Install GoMap', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Install GoMap', exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Docker', exact: true }).click();
  await expect(page.getByRole('tabpanel')).toContainText('docker run --rm');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  expect(errors).toEqual([]);
});

test('all principal routes and local search are available', async ({ page, request, isMobile }) => {
  for (const path of ['install/', 'generated/cli/', 'generated/quick-start/', 'generated/output/', 'docs/detection/', 'docs/udp/', 'benchmarks/', 'releases/', 'security/']) {
    const response = await request.get(path);
    expect(response.ok(), path).toBeTruthy();
    expect(await response.text()).toContain('/gomap/');
  }
  await page.goto('');
  if (isMobile) await page.getByRole('button', { name: 'Menu', exact: true }).click();
  await expect(page.getByRole('link', { name: 'Overview', exact: true })).toHaveAttribute('href', '/gomap/');
  await expect(page.getByRole('link', { name: 'APT repository', exact: true })).toHaveAttribute('href', '/gomap/apt/');
  if (isMobile) await page.getByRole('button', { name: 'Menu', exact: true }).click();
  await page.getByRole('button', { name: /search/i }).first().click();
  await page.getByRole('textbox', { name: 'Search', exact: true }).fill('recover-timeouts');
  await expect(page.locator('.pagefind-ui__result-link').first()).toBeVisible();
  await page.locator('.pagefind-ui__result-link').first().click();
  expect(page.url()).not.toContain('/gomap/gomap/');
  await expect(page.locator('main h1')).toBeVisible();
});
