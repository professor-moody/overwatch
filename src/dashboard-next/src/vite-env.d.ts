/// <reference types="vite/client" />

declare const __OVERWATCH_BUILD_INPUT_SHA__: string;

declare module '*.css' {
  const content: string;
  export default content;
}
