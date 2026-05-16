import { describe, expect, it } from 'vitest';
import puppeteer from 'puppeteer-core';

const smokeUrl = process.env.OVERWATCH_DASHBOARD_SMOKE_URL || '';
const chromePath = process.env.PUPPETEER_EXECUTABLE_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

describe.skipIf(!smokeUrl)('dashboard graph smoke', () => {
  it('renders a nonblank graph canvas for a live dashboard', async () => {
    const browser = await puppeteer.launch({
      executablePath: chromePath,
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 1280, height: 720 });
      await page.goto(smokeUrl, { waitUntil: 'domcontentloaded', timeout: 20_000 });
      await page.evaluate(() => {
        const saved = JSON.stringify({ dc01: { x: 123, y: -45 } });
        localStorage.setItem('overwatch:graph-positions:demo-engagement', saved);
        localStorage.setItem('overwatch:graph-positions:default', saved);
      });
      await page.goto(`${smokeUrl}/graph`, { waitUntil: 'networkidle2', timeout: 20_000 });
      await page.waitForFunction(() => document.querySelectorAll('canvas').length >= 2, { timeout: 10_000 });
      await new Promise(resolve => setTimeout(resolve, 3_000));

      const text = await page.evaluate(() => document.body.innerText);
      expect(text).toContain('Nodes');
      expect(text).toContain('Edges');
      expect(text).toContain('Manual layout');
      expect(text).not.toContain('Graph renderer is not mounted.');
      expect(text).not.toContain('Graph data is loaded, but no renderable nodes were added.');

      await page.evaluate(() => {
        const fit = [...document.querySelectorAll('button')]
          .find(button => button.textContent?.trim() === 'Fit');
        if (!(fit instanceof HTMLButtonElement)) throw new Error('Fit button missing');
        fit.click();
      });
      await new Promise(resolve => setTimeout(resolve, 800));

      const graphCanvasShot = await page.evaluate(async () => {
        const canvases = [...document.querySelectorAll('canvas')]
          .map(canvas => ({ canvas, rect: canvas.getBoundingClientRect() }))
          .filter(item => item.rect.width > 500 && item.rect.height > 300)
          .sort((a, b) => (b.rect.width * b.rect.height) - (a.rect.width * a.rect.height));
        const target = canvases[0]?.canvas;
        if (!target) return 0;
        const blob = await new Promise<Blob | null>(resolve => target.toBlob(resolve));
        return blob?.size || 0;
      });
      expect(graphCanvasShot).toBeGreaterThan(5_000);

      await page.evaluate(() => {
        const layersButton = [...document.querySelectorAll('button')]
          .find(button => button.textContent?.includes('Layers'));
        if (!(layersButton instanceof HTMLButtonElement)) throw new Error('Layers button missing');
        layersButton.click();
      });
      await page.waitForFunction(() => document.body.innerText.includes('Credential flow'), { timeout: 5_000 });

      const layerState = await page.evaluate(() => {
        const buttons = [...document.querySelectorAll('button')];
        const find = (label: string) => buttons.find(button => button.textContent?.includes(label)) as HTMLButtonElement | undefined;
        return {
          credentialDisabled: find('Credential flow')?.disabled ?? true,
          attackPathDisabled: find('Attack path')?.disabled ?? false,
          communityDisabled: find('Community hulls')?.disabled ?? false,
        };
      });
      expect(layerState.credentialDisabled).toBe(false);
      expect(layerState.attackPathDisabled).toBe(true);
      expect(typeof layerState.communityDisabled).toBe('boolean');

      await page.evaluate(() => {
        const credentialFlow = [...document.querySelectorAll('button')]
          .find(button => button.textContent?.includes('Credential flow'));
        if (!(credentialFlow instanceof HTMLButtonElement)) throw new Error('Credential flow layer missing');
        credentialFlow.click();
      });
      await page.waitForFunction(() => {
        const credentialFlow = [...document.querySelectorAll('button')]
          .find(button => button.textContent?.includes('Credential flow'));
        return credentialFlow?.className.includes('text-accent');
      }, { timeout: 5_000 });

      await page.evaluate(() => {
        const reset = [...document.querySelectorAll('button')]
          .find(button => button.textContent?.includes('Reset positions'));
        if (!(reset instanceof HTMLButtonElement)) throw new Error('Reset positions button missing');
        reset.click();
      });
      await page.waitForFunction(() => {
        return !localStorage.getItem('overwatch:graph-positions:demo-engagement')
          || !localStorage.getItem('overwatch:graph-positions:default');
      }, { timeout: 5_000 });

      const screenshot = await page.screenshot({ fullPage: false });
      expect(screenshot.byteLength).toBeGreaterThan(10_000);
    } finally {
      await browser.close();
    }
  }, 40_000);
});
