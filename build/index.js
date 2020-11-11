"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makePluginHook = exports.PostGraphileResponseFastify3 = exports.PostGraphileResponseKoa = exports.PostGraphileResponseNode = exports.PostGraphileResponse = exports.withPostGraphQLContext = exports.watchPostGraphQLSchema = exports.createPostGraphQLSchema = exports.postgraphql = exports.debugPgClient = exports.enhanceHttpServerWithSubscriptions = exports.withPostGraphileContext = exports.watchPostGraphileSchema = exports.createPostGraphileSchema = exports.postgraphile = exports.PostGraphileClassicIdsInflectionPlugin = exports.PostGraphileInflectionPlugin = exports.postGraphileClassicIdsOverrides = exports.postGraphileBaseOverrides = exports.SchemaBuilder = void 0;
const tslib_1 = require("tslib");
tslib_1.__exportStar(require("graphile-utils"), exports);
var postgraphile_core_1 = require("postgraphile-core");
Object.defineProperty(exports, "SchemaBuilder", { enumerable: true, get: function () { return postgraphile_core_1.SchemaBuilder; } });
Object.defineProperty(exports, "postGraphileBaseOverrides", { enumerable: true, get: function () { return postgraphile_core_1.postGraphileBaseOverrides; } });
Object.defineProperty(exports, "postGraphileClassicIdsOverrides", { enumerable: true, get: function () { return postgraphile_core_1.postGraphileClassicIdsOverrides; } });
Object.defineProperty(exports, "PostGraphileInflectionPlugin", { enumerable: true, get: function () { return postgraphile_core_1.PostGraphileInflectionPlugin; } });
Object.defineProperty(exports, "PostGraphileClassicIdsInflectionPlugin", { enumerable: true, get: function () { return postgraphile_core_1.PostGraphileClassicIdsInflectionPlugin; } });
var postgraphile_1 = require("./postgraphile");
Object.defineProperty(exports, "postgraphile", { enumerable: true, get: function () { return postgraphile_1.postgraphile; } });
Object.defineProperty(exports, "createPostGraphileSchema", { enumerable: true, get: function () { return postgraphile_1.createPostGraphileSchema; } });
Object.defineProperty(exports, "watchPostGraphileSchema", { enumerable: true, get: function () { return postgraphile_1.watchPostGraphileSchema; } });
Object.defineProperty(exports, "withPostGraphileContext", { enumerable: true, get: function () { return postgraphile_1.withPostGraphileContext; } });
Object.defineProperty(exports, "enhanceHttpServerWithSubscriptions", { enumerable: true, get: function () { return postgraphile_1.enhanceHttpServerWithSubscriptions; } });
Object.defineProperty(exports, "debugPgClient", { enumerable: true, get: function () { return postgraphile_1.debugPgClient; } });
// Backwards compatability
Object.defineProperty(exports, "postgraphql", { enumerable: true, get: function () { return postgraphile_1.postgraphile; } });
Object.defineProperty(exports, "createPostGraphQLSchema", { enumerable: true, get: function () { return postgraphile_1.createPostGraphileSchema; } });
Object.defineProperty(exports, "watchPostGraphQLSchema", { enumerable: true, get: function () { return postgraphile_1.watchPostGraphileSchema; } });
Object.defineProperty(exports, "withPostGraphQLContext", { enumerable: true, get: function () { return postgraphile_1.withPostGraphileContext; } });
var frameworks_1 = require("./postgraphile/http/frameworks");
Object.defineProperty(exports, "PostGraphileResponse", { enumerable: true, get: function () { return frameworks_1.PostGraphileResponse; } });
Object.defineProperty(exports, "PostGraphileResponseNode", { enumerable: true, get: function () { return frameworks_1.PostGraphileResponseNode; } });
Object.defineProperty(exports, "PostGraphileResponseKoa", { enumerable: true, get: function () { return frameworks_1.PostGraphileResponseKoa; } });
Object.defineProperty(exports, "PostGraphileResponseFastify3", { enumerable: true, get: function () { return frameworks_1.PostGraphileResponseFastify3; } });
var pluginHook_1 = require("./postgraphile/pluginHook");
Object.defineProperty(exports, "makePluginHook", { enumerable: true, get: function () { return pluginHook_1.makePluginHook; } });
const postgraphile_2 = require("./postgraphile");
exports.default = postgraphile_2.postgraphile;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvaW5kZXgudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLHlEQUErQjtBQWEvQix1REFZMkI7QUFSekIsa0hBQUEsYUFBYSxPQUFBO0FBSWIsOEhBQUEseUJBQXlCLE9BQUE7QUFDekIsb0lBQUEsK0JBQStCLE9BQUE7QUFDL0IsaUlBQUEsNEJBQTRCLE9BQUE7QUFDNUIsMklBQUEsc0NBQXNDLE9BQUE7QUFHeEMsK0NBWXdCO0FBWHRCLDRHQUFBLFlBQVksT0FBQTtBQUNaLHdIQUFBLHdCQUF3QixPQUFBO0FBQ3hCLHVIQUFBLHVCQUF1QixPQUFBO0FBQ3ZCLHVIQUFBLHVCQUF1QixPQUFBO0FBQ3ZCLGtJQUFBLGtDQUFrQyxPQUFBO0FBQ2xDLDZHQUFBLGFBQWEsT0FBQTtBQUNiLDBCQUEwQjtBQUMxQiwyR0FBQSxZQUFZLE9BQWU7QUFDM0IsdUhBQUEsd0JBQXdCLE9BQTJCO0FBQ25ELHNIQUFBLHVCQUF1QixPQUEwQjtBQUNqRCxzSEFBQSx1QkFBdUIsT0FBMEI7QUFHbkQsNkRBS3dDO0FBSnRDLGtIQUFBLG9CQUFvQixPQUFBO0FBQ3BCLHNIQUFBLHdCQUF3QixPQUFBO0FBQ3hCLHFIQUFBLHVCQUF1QixPQUFBO0FBQ3ZCLDBIQUFBLDRCQUE0QixPQUFBO0FBRzlCLHdEQUErRTtBQUF0RSw0R0FBQSxjQUFjLE9BQUE7QUFFdkIsaURBQThDO0FBQzlDLGtCQUFlLDJCQUFZLENBQUMifQ==