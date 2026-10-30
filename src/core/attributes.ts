/**
 * Get a list of all values matching the path (including wildcards).
 */
export const getAttributeValues = (
  attributes: Record<string, any> | null | undefined,
  path: string[],
): any[] => {
  if (attributes === undefined || attributes === null) {
    return [];
  }

  if (path.length === 0) {
    return [attributes];
  }

  const name = path[0];

  switch (name) {
    case '*':
      const keys = Object.keys(attributes as Record<string, any>);
      let values: Record<string, string>[] = [];

      for (const key of keys) {
        const result = getAttributeValues(
          attributes[key] as Record<string, any>,
          path.slice(1),
        );

        // If a single sub-path fails to evaluate fail the entire traversal.
        if (result.length === 0) {
          values = [];
          break;
        } else {
          values = values.concat(result);
        }
      }

      return values;
    case '%keys':
      return getAttributeValues(
        Object.keys(attributes as Record<string, any>),
        path.slice(1),
      );
    default:
      const unescapedName = name.replace(/^%%/, '%');
      return getAttributeValues(
        attributes[unescapedName] as Record<string, any>,
        path.slice(1),
      );
  }
};

/**
 * Get the attribute value identified by path.
 *
 * @param {object} attributes attributes as nested objects
 * @param {string} path string path (e.g. 'user.groups')
 */
export const getAttribute = (
  attributes: Record<string, any> | undefined,
  path: string,
) => {
  const name = path.split('.');
  return getAttributeValues(attributes, name)[0];
};

/**
 * Return true iff left is a path prefix of right
 */
export const isPathPrefix = (left: string, right: string) => {
  const lhs = left.split('.');
  const rhs = right.split('.');

  if (lhs.length > rhs.length) {
    return false;
  }

  for (let i = 0; i < lhs.length; ++i) {
    if (lhs[i] !== rhs[i]) {
      return false;
    }
  }

  return true;
};
