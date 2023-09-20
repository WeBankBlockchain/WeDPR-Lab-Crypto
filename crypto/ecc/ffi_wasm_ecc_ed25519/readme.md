# 编译生成wasm

`wasm-pack build`命令可以使用不同的目标参数，用于生成不同平台和环境可用的 WebAssembly（Wasm）模块。以下是`wasm-pack`库当前版本（v0.10.0）中支持的目标选项：

1. `bundler`（默认）：生成可以在现代浏览器和支持 ES6 模块的环境中使用的 Wasm 模块，打包为单个文件。

2. `web`：生成可以在现代浏览器中直接使用的 Wasm 模块，打包为单个文件。

3. `no-modules`：生成不依赖 ES6 模块的 Wasm 输出，适用于在没有模块系统的环境下使用。

4. `nodejs`：生成可以在 Node.js 环境中使用的 Wasm 模块，使用 CommonJS 模块进行导出。

5. `webworker`：生成用于 Web Worker 的 Wasm 模块，打包为单个文件。

6. `nodejs-esm`：生成可以在支持 ES6 模块的 Node.js 环境中使用的 Wasm 模块。

你可以根据你的需求，选择合适的构建目标，以便在不同的环境中正确地使用和部署生成的 Wasm 模块。使用对应的`--target`选项来选择特定的目标。例如：`wasm-pack build --target web`将生成支持现代浏览器的 Wasm 模块。