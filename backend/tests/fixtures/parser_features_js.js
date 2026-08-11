/**
 * Exercises parser features that aren't security-relevant on their own
 * but matter for getting function/class metadata right: export
 * unwrapping, default parameters, rest parameters, and (in the .ts
 * sibling below) TypeScript-typed parameters.
 */

export function exportedFunction(a, b) {
  return a + b;
}

export default function exportedDefaultFunction() {
  return 1;
}

export const exportedArrow = (x) => x * 2;

export class ExportedClass {
  method() {
    return 1;
  }
}

function paramsWithDefaultsAndRest(a, b = 2, ...rest) {
  return [a, b, ...rest];
}

class ComponentWithArrowFieldMethod {
  // Common React pattern: a class field assigned an arrow function,
  // rather than a `method_definition`. Needs its own extraction path
  // since it's a different node shape (field_definition).
  handleClick = (event) => {
    return event;
  };
}
