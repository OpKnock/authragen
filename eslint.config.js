module.exports = [
  {
    ignores: ["node_modules/**", "dist/**", "docs/.vitepress/dist/**", "coverage/**"]
  },
  {
    files: ["**/*.js", "**/*.cjs", "**/*.mjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "commonjs"
    },
    rules: {}
  }
];
