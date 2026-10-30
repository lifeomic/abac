import RealAjv from 'ajv';

afterEach(() => {
  vi.doUnmock('ajv');
  vi.resetModules();
});

test.each([
  [
    'ajv 6, whose default import is the class',
    () =>
      class Ajv {
        constructor(options: object) {
          return new RealAjv(options);
        }
      },
  ],
  ['ajv 7, whose default import under Node ESM is the exports object', () => ({ default: RealAjv })],
])('validates with %s', async (_, defaultExport) => {
  vi.doMock('ajv', () => ({ default: defaultExport() }));
  const { validate } = await import('../src/validation.js');

  expect(validate({ rules: { readData: true } })).toBe(true);
  expect(() => validate({ rules: 'readData' } as never)).toThrow(/rules/);
});
