"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isEmpty = void 0;
/* eslint-disable @typescript-eslint/no-explicit-any,require-atomic-updates */
const graphql_1 = require("graphql");
const extendedFormatError_1 = require("../extendedFormatError");
const pluginHook_1 = require("../pluginHook");
const setupServerSentEvents_1 = require("./setupServerSentEvents");
const withPostGraphileContext_1 = require("../withPostGraphileContext");
const lru_1 = require("@graphile/lru");
const chalk_1 = require("chalk");
const Debugger = require("debug"); // tslint:disable-line variable-name
const httpError = require("http-errors");
const parseUrl = require("parseurl");
const finalHandler = require("finalhandler");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const isKoaApp = (a, b) => a.req && a.res && typeof b === 'function';
const CACHE_MULTIPLIER = 100000;
const ALLOW_EXPLAIN_PLACEHOLDER = '__SHOULD_ALLOW_EXPLAIN__';
const noop = () => {
    /* noop */
};
const { createHash } = crypto;
/**
 * The favicon file in `Buffer` format. We can send a `Buffer` directly to the
 * client.
 *
 * @type {Buffer}
 */
const favicon_ico_1 = require("../../assets/favicon.ico");
/**
 * The GraphiQL HTML file as a string. We need it to be a string, because we
 * will use a regular expression to replace some variables.
 */
const graphiql_html_1 = require("../../assets/graphiql.html");
const subscriptions_1 = require("./subscriptions");
const frameworks_1 = require("./frameworks");
/**
 * When writing JSON to the browser, we need to be careful that it doesn't get
 * interpretted as HTML.
 */
const JS_ESCAPE_LOOKUP = {
    '<': '\\u003c',
    '>': '\\u003e',
    '/': '\\u002f',
    '\u2028': '\\u2028',
    '\u2029': '\\u2029',
};
function safeJSONStringify(obj) {
    return JSON.stringify(obj).replace(/[<>/\u2028\u2029]/g, chr => JS_ESCAPE_LOOKUP[chr]);
}
/**
 * When people webpack us up, e.g. for lambda, if they don't want GraphiQL then
 * they can seriously reduce bundle size by omitting the assets.
 */
const shouldOmitAssets = process.env.POSTGRAPHILE_OMIT_ASSETS === '1';
// Used by `createPostGraphileHttpRequestHandler`
let lastString;
let lastHash;
const calculateQueryHash = (queryString) => {
    if (queryString !== lastString) {
        lastString = queryString;
        lastHash = createHash('sha1').update(queryString).digest('base64');
    }
    return lastHash;
};
// Fast way of checking if an object is empty,
// faster than `Object.keys(value).length === 0`.
// NOTE: we don't need a `hasOwnProperty` call here because isEmpty is called
// with an `Object.create(null)` object, so it has no no-own properties.
/* tslint:disable forin */
function isEmpty(value) {
    for (const _key in value) {
        return false;
    }
    return true;
}
exports.isEmpty = isEmpty;
/* tslint:enable forin */
const isPostGraphileDevelopmentMode = process.env.POSTGRAPHILE_ENV === 'development';
const debugGraphql = Debugger('postgraphile:graphql');
const debugRequest = Debugger('postgraphile:request');
/**
 * We need to be able to share the withPostGraphileContext logic between HTTP
 * and websockets
 */
function withPostGraphileContextFromReqResGenerator(options) {
    const { pgSettings: pgSettingsGenerator, allowExplain: allowExplainGenerator, jwtSecret, additionalGraphQLContextFromRequest, } = options;
    return async (req, res, moreOptions, fn) => {
        const jwtToken = jwtSecret ? getJwtToken(req) : null;
        const additionalContext = typeof additionalGraphQLContextFromRequest === 'function'
            ? await additionalGraphQLContextFromRequest(req, res)
            : null;
        const pgSettings = typeof pgSettingsGenerator === 'function'
            ? await pgSettingsGenerator(req)
            : pgSettingsGenerator;
        const allowExplain = typeof allowExplainGenerator === 'function'
            ? await allowExplainGenerator(req)
            : allowExplainGenerator;
        return withPostGraphileContext_1.default({
            ...options,
            jwtToken,
            pgSettings,
            explain: allowExplain && req.headers['x-postgraphile-explain'] === 'on',
            ...moreOptions,
        }, context => {
            const graphqlContext = additionalContext
                ? { ...additionalContext, ...context }
                : context;
            return fn(graphqlContext);
        });
    };
}
/**
 * Creates a GraphQL request handler that can support many different `http` frameworks, including:
 *
 * - Native Node.js `http`.
 * - `connect`.
 * - `express`.
 * - `koa` (2.0).
 */
function createPostGraphileHttpRequestHandler(options) {
    const MEGABYTE = 1024 * 1024;
    const { getGqlSchema, pgPool, pgSettings, pgDefaultRole, queryCacheMaxSize = 50 * MEGABYTE, extendedErrors, showErrorStack, watchPg, disableQueryLog, enableQueryBatching, } = options;
    const subscriptions = !!options.subscriptions;
    const live = !!options.live;
    const enhanceGraphiql = options.enhanceGraphiql === false ? false : !!options.enhanceGraphiql || subscriptions || live;
    const enableCors = !!options.enableCors || isPostGraphileDevelopmentMode;
    const graphiql = options.graphiql === true;
    if (options['absoluteRoutes']) {
        throw new Error('Sorry - the `absoluteRoutes` setting has been replaced with `externalUrlBase` which solves the issue in a cleaner way. Please update your settings. Thank you for testing a PostGraphile pre-release 🙏');
    }
    // Using let because we might override it on the first request.
    let externalUrlBase = options.externalUrlBase;
    if (externalUrlBase && externalUrlBase.endsWith('/')) {
        throw new Error('externalUrlBase must not end with a slash (`/`)');
    }
    const pluginHook = pluginHook_1.pluginHookFromOptions(options);
    const origGraphiqlHtml = pluginHook('postgraphile:graphiql:html', graphiql_html_1.default, { options });
    if (pgDefaultRole && typeof pgSettings === 'function') {
        throw new Error('pgDefaultRole cannot be combined with pgSettings(req) - please remove pgDefaultRole and instead always return a `role` key from pgSettings(req).');
    }
    if (pgDefaultRole &&
        pgSettings &&
        typeof pgSettings === 'object' &&
        Object.keys(pgSettings)
            .map(s => s.toLowerCase())
            .includes('role')) {
        throw new Error('pgDefaultRole cannot be combined with pgSettings.role - please use one or the other.');
    }
    if (graphiql && shouldOmitAssets) {
        throw new Error('Cannot enable GraphiQL when POSTGRAPHILE_OMIT_ASSETS is set');
    }
    // Gets the route names for our GraphQL endpoint, and our GraphiQL endpoint.
    const graphqlRoute = options.graphqlRoute || '/graphql';
    const graphiqlRoute = options.graphiqlRoute || '/graphiql';
    // Set the request credential behavior in graphiql.
    const graphiqlCredentials = options.graphiqlCredentials || 'same-origin';
    const eventStreamRoute = options.eventStreamRoute || `${graphqlRoute.replace(/\/+$/, '')}/stream`;
    const externalGraphqlRoute = options.externalGraphqlRoute;
    const externalEventStreamRoute = options.externalEventStreamRoute ||
        (externalGraphqlRoute && !options.eventStreamRoute
            ? `${externalGraphqlRoute.replace(/\/+$/, '')}/stream`
            : undefined);
    // Throw an error of the GraphQL and GraphiQL routes are the same.
    if (graphqlRoute === graphiqlRoute)
        throw new Error(`Cannot use the same route, '${graphqlRoute}', for both GraphQL and GraphiQL. Please use different routes.`);
    // Formats an error using the default GraphQL `formatError` function, and
    // custom formatting using some other options.
    const formatError = (error) => {
        // Get the appropriate formatted error object, including any extended error
        // fields if the user wants them.
        const formattedError = extendedErrors && extendedErrors.length
            ? extendedFormatError_1.extendedFormatError(error, extendedErrors)
            : graphql_1.formatError(error);
        // If the user wants to see the error’s stack, let’s add it to the
        // formatted error.
        if (showErrorStack)
            formattedError['stack'] =
                error.stack != null && showErrorStack === 'json' ? error.stack.split('\n') : error.stack;
        return formattedError;
    };
    const DEFAULT_HANDLE_ERRORS = (errors) => errors.map(formatError);
    const handleErrors = options.handleErrors || DEFAULT_HANDLE_ERRORS;
    // Define a list of middlewares that will get run before our request handler.
    // Note though that none of these middlewares will intercept a request (i.e.
    // not call `next`). Middlewares that handle a request like favicon
    // middleware will result in a promise that never resolves, and we don’t
    // want that.
    const bodyParserMiddlewares = [
        // Parse JSON bodies.
        bodyParser.json({ limit: options.bodySizeLimit }),
        // Parse URL encoded bodies (forms).
        bodyParser.urlencoded({ extended: false, limit: options.bodySizeLimit }),
        // Parse `application/graphql` content type bodies as text.
        bodyParser.text({ type: 'application/graphql', limit: options.bodySizeLimit }),
    ];
    // We'll turn this into one function now so it can be better JIT optimised
    const bodyParserMiddlewaresComposed = bodyParserMiddlewares.reduce((parent, fn) => {
        return (req, res, next) => {
            parent(req, res, error => {
                if (error) {
                    return next(error);
                }
                fn(req, res, next);
            });
        };
    }, (_req, _res, next) => next());
    // And we really want that function to be await-able
    const parseBody = (req, res) => new Promise((resolve, reject) => {
        bodyParserMiddlewaresComposed(req, 
        // Note: middleware here doesn't actually use the response, but we pass
        // the underlying value so types match up.
        res.getNodeServerResponse(), (error) => {
            if (error) {
                reject(error);
            }
            else {
                resolve();
            }
        });
    });
    // We only need to calculate the graphiql HTML once; but we need to receive the first request to do so.
    let graphiqlHtml;
    const withPostGraphileContextFromReqRes = withPostGraphileContextFromReqResGenerator(options);
    const staticValidationRules = pluginHook('postgraphile:validationRules:static', graphql_1.specifiedRules, {
        options,
    });
    const cacheSize = Math.ceil(queryCacheMaxSize / CACHE_MULTIPLIER);
    // Do not create an LRU for cache size < 2 because @graphile/lru will baulk.
    const cacheEnabled = cacheSize >= 2;
    const queryCache = cacheEnabled ? new lru_1.default({ maxLength: cacheSize }) : null;
    let lastGqlSchema;
    const parseQuery = (gqlSchema, queryString) => {
        if (gqlSchema !== lastGqlSchema) {
            if (queryCache) {
                queryCache.reset();
            }
            lastGqlSchema = gqlSchema;
        }
        // Only cache queries that are less than 100kB, we don't want DOS attacks
        // attempting to exhaust our memory.
        const canCache = cacheEnabled && queryString.length < 100000;
        const hash = canCache ? calculateQueryHash(queryString) : null;
        const result = canCache ? queryCache.get(hash) : null;
        if (result) {
            return result;
        }
        else {
            const source = new graphql_1.Source(queryString, 'GraphQL Http Request');
            let queryDocumentAst;
            // Catch an errors while parsing so that we can set the `statusCode` to
            // 400. Otherwise we don’t need to parse this way.
            try {
                queryDocumentAst = graphql_1.parse(source);
            }
            catch (error) {
                error.statusCode = 400;
                throw error;
            }
            if (debugRequest.enabled)
                debugRequest('GraphQL query is parsed.');
            // Validate our GraphQL query using given rules.
            const validationErrors = graphql_1.validate(gqlSchema, queryDocumentAst, staticValidationRules);
            const cacheResult = {
                queryDocumentAst,
                validationErrors,
                length: queryString.length,
            };
            if (canCache) {
                queryCache.set(hash, cacheResult);
            }
            return cacheResult;
        }
    };
    let firstRequestHandler = req => {
        // Never be called again
        firstRequestHandler = null;
        let graphqlRouteForWs = graphqlRoute;
        const { pathname = '' } = parseUrl(req) || {};
        const { pathname: originalPathname = '' } = parseUrl.original(req) || {};
        if (originalPathname !== pathname && originalPathname.endsWith(pathname)) {
            const base = originalPathname.substr(0, originalPathname.length - pathname.length);
            // Our websocket GraphQL route must be at a different place
            graphqlRouteForWs = base + graphqlRouteForWs;
            if (externalUrlBase == null) {
                // User hasn't specified externalUrlBase; let's try and guess it
                // We were mounted on a subpath (e.g. `app.use('/path/to', postgraphile(...))`).
                // Figure out our externalUrlBase for ourselves.
                externalUrlBase = base;
            }
        }
        // Make sure we have a string, at least
        externalUrlBase = externalUrlBase || '';
        // Takes the original GraphiQL HTML file and replaces the default config object.
        graphiqlHtml = origGraphiqlHtml
            ? origGraphiqlHtml.replace(/<\/head>/, `  <script>window.POSTGRAPHILE_CONFIG=${safeJSONStringify({
                graphqlUrl: externalGraphqlRoute || `${externalUrlBase}${graphqlRoute}`,
                streamUrl: watchPg
                    ? externalEventStreamRoute || `${externalUrlBase}${eventStreamRoute}`
                    : null,
                enhanceGraphiql,
                subscriptions,
                allowExplain: typeof options.allowExplain === 'function'
                    ? ALLOW_EXPLAIN_PLACEHOLDER
                    : !!options.allowExplain,
                credentials: graphiqlCredentials,
            })};</script>\n  </head>`)
            : null;
        if (subscriptions) {
            const server = req && req.connection && req.connection['server'];
            if (!server) {
                // tslint:disable-next-line no-console
                console.warn("Failed to find server to add websocket listener to, you'll need to call `enhanceHttpServerWithSubscriptions` manually");
            }
            else {
                // Relying on this means that a normal request must come in before an
                // upgrade attempt. It's better to call it manually.
                subscriptions_1.enhanceHttpServerWithSubscriptions(server, middleware, { graphqlRoute: graphqlRouteForWs });
            }
        }
    };
    /*
     * If we're not in watch mode, then avoid the cost of `await`ing the schema
     * on every tick by having it available once it was generated.
     */
    let theOneAndOnlyGraphQLSchema = null;
    if (!watchPg) {
        getGqlSchema()
            .then(schema => {
            theOneAndOnlyGraphQLSchema = schema;
        })
            .catch(noop);
    }
    function neverReject(middlewareName, middleware) {
        return async (res) => {
            try {
                await middleware(res);
            }
            catch (e) {
                console.error(`An unexpected error occurred whilst processing '${middlewareName}'; this indicates a bug. The connection will be terminated.`);
                console.error(e);
                try {
                    // At least terminate the connection
                    res.statusCode = 500;
                    res.end();
                }
                catch (e) {
                    /*NOOP*/
                }
            }
        };
    }
    /**
     * The actual request handler. It’s an async function so it will return a
     * promise when complete. If the function doesn’t handle anything, it calls
     * `next` to let the next middleware try and handle it. If the function
     * throws an error, it's up to the wrapping middleware (imaginatively named
     * `middleware`, below) to handle the error. Frameworks like Koa have
     * middlewares reject a promise on error, whereas Express requires you pass
     * the error to the `next(err)` function.
     */
    const requestHandler = async (responseHandler, next) => {
        const res = responseHandler;
        const incomingReq = res.getNodeServerRequest();
        const nodeRes = res.getNodeServerResponse();
        // You can use this hook either to modify the incoming request or to tell
        // PostGraphile not to handle the request further (return null). NOTE: if
        // you return `null` from this hook then you are also responsible for
        // calling `next()` (should that be required).
        const req = pluginHook('postgraphile:http:handler', incomingReq, {
            options,
            res: nodeRes,
            next,
        });
        if (req == null) {
            return;
        }
        const { pathname = '' } = parseUrl(req) || {};
        // Certain things depend on externalUrlBase, which we guess if the user
        // doesn't supply it, so we calculate them on the first request. After
        // first request, this function becomes a NOOP
        if (firstRequestHandler)
            firstRequestHandler(req);
        // ======================================================================
        // GraphQL Watch Stream
        // ======================================================================
        if (watchPg) {
            // Setup an event stream so we can broadcast events to graphiql, etc.
            if (pathname === eventStreamRoute || pathname === '/_postgraphile/stream') {
                return eventStreamRouteHandler(res);
            }
        }
        const isGraphqlRoute = pathname === graphqlRoute;
        // ========================================================================
        // Serve GraphiQL and Related Assets
        // ========================================================================
        if (!shouldOmitAssets && graphiql && !isGraphqlRoute) {
            // ======================================================================
            // Favicon
            // ======================================================================
            // If this is the favicon path and it has not yet been handled, let us
            // serve our GraphQL favicon.
            if (pathname === '/favicon.ico') {
                return faviconRouteHandler(res);
            }
            // ======================================================================
            // GraphiQL HTML
            // ======================================================================
            // If this is the GraphiQL route, show GraphiQL and stop execution.
            if (pathname === graphiqlRoute) {
                // If we are developing PostGraphile, instead just redirect.
                if (isPostGraphileDevelopmentMode) {
                    res.statusCode = 302;
                    res.setHeader('Location', 'http://localhost:5783');
                    res.end();
                    return;
                }
                return graphiqlRouteHandler(res);
            }
        }
        if (isGraphqlRoute) {
            return graphqlRouteHandler(res);
        }
        else {
            // This request wasn't for us.
            return next();
        }
    };
    const eventStreamRouteHandler = neverReject('eventStreamRouteHandler', async function eventStreamRouteHandler(res) {
        try {
            const req = res.getNodeServerRequest();
            // Add our CORS headers to be good web citizens (there are perf
            // implications though so be careful!)
            //
            // Always enable CORS when developing PostGraphile because GraphiQL will be
            // on port 5783.
            if (enableCors)
                addCORSHeaders(res);
            if (req.headers.accept !== 'text/event-stream') {
                res.statusCode = 405;
                res.end();
                return;
            }
            setupServerSentEvents_1.default(res, options);
        }
        catch (e) {
            console.error('Unexpected error occurred in eventStreamRouteHandler');
            console.error(e);
            res.statusCode = 500;
            res.end();
        }
    });
    const faviconRouteHandler = neverReject('faviconRouteHandler', async function faviconRouteHandler(res) {
        const req = res.getNodeServerRequest();
        // If this is the wrong method, we should let the client know.
        if (!(req.method === 'GET' || req.method === 'HEAD')) {
            res.statusCode = req.method === 'OPTIONS' ? 200 : 405;
            res.setHeader('Allow', 'GET, HEAD, OPTIONS');
            res.end();
            return;
        }
        // Otherwise we are good and should pipe the favicon to the browser.
        res.statusCode = 200;
        res.setHeader('Cache-Control', 'public, max-age=86400');
        res.setHeader('Content-Type', 'image/x-icon');
        // End early if the method is `HEAD`.
        if (req.method === 'HEAD') {
            res.end();
            return;
        }
        res.end(favicon_ico_1.default);
    });
    const graphiqlRouteHandler = neverReject('graphiqlRouteHandler', async function graphiqlRouteHandler(res) {
        const req = res.getNodeServerRequest();
        if (firstRequestHandler)
            firstRequestHandler(req);
        // If using the incorrect method, let the user know.
        if (!(req.method === 'GET' || req.method === 'HEAD')) {
            res.statusCode = req.method === 'OPTIONS' ? 200 : 405;
            res.setHeader('Allow', 'GET, HEAD, OPTIONS');
            res.end();
            return;
        }
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
        // End early if the method is `HEAD`.
        if (req.method === 'HEAD') {
            res.end();
            return;
        }
        // Actually renders GraphiQL.
        if (graphiqlHtml && typeof options.allowExplain === 'function') {
            res.end(graphiqlHtml.replace(`"${ALLOW_EXPLAIN_PLACEHOLDER}"`, // Because JSON escaped
            JSON.stringify(!!(await options.allowExplain(req)))));
        }
        else {
            res.end(graphiqlHtml);
        }
    });
    const graphqlRouteHandler = neverReject('graphqlRouteHandler', async function graphqlRouteHandler(res) {
        const req = res.getNodeServerRequest();
        if (firstRequestHandler)
            firstRequestHandler(req);
        // Add our CORS headers to be good web citizens (there are perf
        // implications though so be careful!)
        //
        // Always enable CORS when developing PostGraphile because GraphiQL will be
        // on port 5783.
        if (enableCors)
            addCORSHeaders(res);
        // ========================================================================
        // Execute GraphQL Queries
        // ========================================================================
        // If we didn’t call `next` above, all requests will return 200 by default!
        res.statusCode = 200;
        if (watchPg) {
            // Inform GraphiQL and other clients that they can subscribe to events
            // (such as the schema being updated) at the following URL
            res.setHeader('X-GraphQL-Event-Stream', externalEventStreamRoute || `${externalUrlBase}${eventStreamRoute}`);
        }
        // Don’t execute our GraphQL stuffs for `OPTIONS` requests.
        if (req.method === 'OPTIONS') {
            res.statusCode = 200;
            res.end();
            return;
        }
        // The `result` will be used at the very end in our `finally` block.
        // Statements inside the `try` will assign to `result` when they get
        // a result. We also keep track of `params`.
        let paramsList;
        let results = [];
        const queryTimeStart = !disableQueryLog && process.hrtime();
        let pgRole;
        if (debugRequest.enabled)
            debugRequest('GraphQL query request has begun.');
        let returnArray = false;
        // This big `try`/`catch`/`finally` block represents the execution of our
        // GraphQL query. All errors thrown in this block will be returned to the
        // client as GraphQL errors.
        try {
            // First thing we need to do is get the GraphQL schema for this request.
            // It should never really change unless we are in watch mode.
            const gqlSchema = theOneAndOnlyGraphQLSchema || (await getGqlSchema());
            // Note that we run our middleware after we make sure we are on the
            // correct route. This is so that if our middleware modifies the `req` or
            // `res` objects, only we downstream will see the modifications.
            //
            // We also run our middleware inside the `try` so that we get the GraphQL
            // error reporting style for syntax errors.
            await parseBody(req, res);
            // If this is not one of the correct methods, throw an error.
            if (req.method !== 'POST') {
                res.setHeader('Allow', 'POST, OPTIONS');
                throw httpError(405, 'Only `POST` requests are allowed.');
            }
            // Get the parameters we will use to run a GraphQL request. `params` may
            // include:
            //
            // - `query`: The required GraphQL query string.
            // - `variables`: An optional JSON object containing GraphQL variables.
            // - `operationName`: The optional name of the GraphQL operation we will
            //   be executing.
            const body = req.body;
            paramsList = typeof body === 'string' ? { query: body } : body;
            // Validate our paramsList object a bit.
            if (paramsList == null)
                throw httpError(400, 'Must provide an object parameters, not nullish value.');
            if (typeof paramsList !== 'object')
                throw httpError(400, `Expected parameter object, not value of type '${typeof paramsList}'.`);
            if (Array.isArray(paramsList)) {
                if (!enableQueryBatching) {
                    throw httpError(501, 'Batching queries as an array is currently unsupported. Please provide a single query object.');
                }
                else {
                    returnArray = true;
                }
            }
            else {
                paramsList = [paramsList];
            }
            paramsList = pluginHook('postgraphile:httpParamsList', paramsList, {
                options,
                req,
                res,
                returnArray,
                httpError,
            });
            results = await Promise.all(paramsList.map(async (params) => {
                let queryDocumentAst = null;
                let result;
                const meta = Object.create(null);
                try {
                    if (!params)
                        throw httpError(400, 'Invalid query structure.');
                    const { query, operationName } = params;
                    let { variables } = params;
                    if (!query)
                        throw httpError(400, 'Must provide a query string.');
                    // If variables is a string, we assume it is a JSON string and that it
                    // needs to be parsed.
                    if (typeof variables === 'string') {
                        // If variables is just an empty string, we should set it to null and
                        // ignore it.
                        if (variables === '') {
                            variables = null;
                        }
                        else {
                            // Otherwise, let us try to parse it as JSON.
                            try {
                                variables = JSON.parse(variables);
                            }
                            catch (error) {
                                error.statusCode = 400;
                                throw error;
                            }
                        }
                    }
                    // Throw an error if `variables` is not an object.
                    if (variables != null && typeof variables !== 'object')
                        throw httpError(400, `Variables must be an object, not '${typeof variables}'.`);
                    // Throw an error if `operationName` is not a string.
                    if (operationName != null && typeof operationName !== 'string')
                        throw httpError(400, `Operation name must be a string, not '${typeof operationName}'.`);
                    let validationErrors;
                    ({ queryDocumentAst, validationErrors } = parseQuery(gqlSchema, query));
                    if (validationErrors.length === 0) {
                        // You are strongly encouraged to use
                        // `postgraphile:validationRules:static` if possible - you should
                        // only use this one if you need access to variables.
                        const moreValidationRules = pluginHook('postgraphile:validationRules', [], {
                            options,
                            req,
                            res,
                            variables,
                            operationName,
                            meta,
                        });
                        if (moreValidationRules.length) {
                            validationErrors = graphql_1.validate(gqlSchema, queryDocumentAst, moreValidationRules);
                        }
                    }
                    // If we have some validation errors, don’t execute the query. Instead
                    // send the errors to the client with a `400` code.
                    if (validationErrors.length > 0) {
                        result = { errors: validationErrors, statusCode: 400 };
                    }
                    else if (!queryDocumentAst) {
                        throw new Error('Could not process query');
                    }
                    else {
                        if (debugRequest.enabled)
                            debugRequest('GraphQL query is validated.');
                        // Lazily log the query. If this debugger isn’t enabled, don’t run it.
                        if (debugGraphql.enabled)
                            debugGraphql('%s', graphql_1.print(queryDocumentAst).replace(/\s+/g, ' ').trim());
                        result = await withPostGraphileContextFromReqRes(req, 
                        // For backwards compatibilty we must pass the actual node request object.
                        res.getNodeServerResponse(), {
                            singleStatement: false,
                            queryDocumentAst,
                            variables,
                            operationName,
                        }, (graphqlContext) => {
                            pgRole = graphqlContext.pgRole;
                            const graphqlResult = graphql_1.execute(gqlSchema, queryDocumentAst, null, graphqlContext, variables, operationName);
                            if (typeof graphqlContext.getExplainResults === 'function') {
                                return Promise.resolve(graphqlResult).then(async (obj) => ({
                                    ...obj,
                                    // Add our explain data
                                    explain: await graphqlContext.getExplainResults(),
                                }));
                            }
                            else {
                                return graphqlResult;
                            }
                        });
                    }
                }
                catch (error) {
                    result = {
                        errors: [error],
                        statusCode: error.status || error.statusCode || 500,
                    };
                    // If the status code is 500, let’s log our error.
                    if (result.statusCode === 500)
                        // tslint:disable-next-line no-console
                        console.error(error.stack);
                }
                finally {
                    // Format our errors so the client doesn’t get the full thing.
                    if (result && result.errors) {
                        result.errors = handleErrors(result.errors, req, res);
                    }
                    if (!isEmpty(meta)) {
                        result.meta = meta;
                    }
                    result = pluginHook('postgraphile:http:result', result, {
                        options,
                        returnArray,
                        queryDocumentAst,
                        req,
                        pgRole,
                    });
                    // Log the query. If this debugger isn’t enabled, don’t run it.
                    if (!disableQueryLog && queryDocumentAst) {
                        // To appease TypeScript
                        const definitelyQueryDocumentAst = queryDocumentAst;
                        // We must reference this before it's deleted!
                        const resultStatusCode = result.statusCode;
                        const timeDiff = queryTimeStart && process.hrtime(queryTimeStart);
                        setImmediate(() => {
                            const prettyQuery = graphql_1.print(definitelyQueryDocumentAst)
                                .replace(/\s+/g, ' ')
                                .trim();
                            const errorCount = (result.errors || []).length;
                            const ms = timeDiff[0] * 1e3 + timeDiff[1] * 1e-6;
                            let message;
                            if (resultStatusCode === 401) {
                                // Users requested that JWT errors were raised differently:
                                //
                                //   https://github.com/graphile/postgraphile/issues/560
                                message = chalk_1.default.red(`401 authentication error`);
                            }
                            else if (resultStatusCode === 403) {
                                message = chalk_1.default.red(`403 forbidden error`);
                            }
                            else {
                                message = chalk_1.default[errorCount === 0 ? 'green' : 'red'](`${errorCount} error(s)`);
                            }
                            // tslint:disable-next-line no-console
                            console.log(`${message} ${pgRole != null ? `as ${chalk_1.default.magenta(pgRole)} ` : ''}in ${chalk_1.default.grey(`${ms.toFixed(2)}ms`)} :: ${prettyQuery}`);
                        });
                    }
                    if (debugRequest.enabled)
                        debugRequest('GraphQL query has been executed.');
                }
                return result;
            }));
        }
        catch (error) {
            // Set our status code and send the client our results!
            if (res.statusCode === 200)
                res.statusCode = error.status || error.statusCode || 500;
            // Overwrite entire response
            returnArray = false;
            results = [{ errors: handleErrors([error], req, res) }];
            // If the status code is 500, let’s log our error.
            if (res.statusCode === 500) {
                // tslint:disable-next-line no-console
                console.error(error.stack);
            }
        }
        finally {
            // Finally, we send the client the results.
            if (!returnArray) {
                if (res.statusCode === 200 && results[0].statusCode) {
                    res.statusCode = results[0].statusCode;
                }
                results[0].statusCode = undefined;
            }
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            const { statusCode, result } = pluginHook('postgraphile:http:end', {
                statusCode: res.statusCode,
                result: returnArray ? results : results[0],
            }, {
                options,
                returnArray,
                req,
                // For backwards compatibility, the underlying response object.
                res: res.getNodeServerResponse(),
            });
            if (statusCode) {
                res.statusCode = statusCode;
            }
            res.end(JSON.stringify(result));
            if (debugRequest.enabled) {
                debugRequest('GraphQL ' + (returnArray ? 'queries' : 'query') + ' request finished.');
            }
        }
    });
    /**
     * A polymorphic request handler that should detect what `http` framework is
     * being used and specifically handle that framework.
     *
     * Supported frameworks include:
     *
     * - Native Node.js `http`.
     * - `connect`.
     * - `express`.
     * - `koa` (2.0).
     */
    const middleware = (a, b, c) => {
        // If are arguments look like the arguments to koa middleware, this is
        // `koa` middleware.
        if (isKoaApp(a, b)) {
            // Set the correct `koa` variable names…
            const ctx = a;
            const next = b;
            const responseHandler = new frameworks_1.PostGraphileResponseKoa(ctx, next);
            // Execute our request handler. If an error is thrown, we don’t call
            // `next` with an error. Instead we return the promise and let `koa`
            // handle the error.
            return requestHandler(responseHandler, next);
        }
        else {
            // Set the correct `connect` style variable names. If there was no `next`
            // defined (likely the case if the client is using `http`) we use the
            // final handler.
            const req = a;
            const res = b;
            const next = c || finalHandler(req, res);
            const responseHandler = new frameworks_1.PostGraphileResponseNode(req, res, next);
            // Execute our request handler. If the request errored out, call `next` with the error.
            requestHandler(responseHandler, next).catch(next);
            // No return value.
        }
    };
    middleware.getGraphQLSchema = getGqlSchema;
    middleware.formatError = formatError;
    middleware.pgPool = pgPool;
    middleware.withPostGraphileContextFromReqRes = withPostGraphileContextFromReqRes;
    middleware.handleErrors = handleErrors;
    middleware.options = options;
    middleware.graphqlRoute = graphqlRoute;
    middleware.graphqlRouteHandler = graphqlRouteHandler;
    middleware.graphiqlRoute = graphiqlRoute;
    middleware.graphiqlRouteHandler = graphiql ? graphiqlRouteHandler : null;
    middleware.faviconRouteHandler = graphiql ? faviconRouteHandler : null;
    middleware.eventStreamRoute = eventStreamRoute;
    middleware.eventStreamRouteHandler = watchPg ? eventStreamRouteHandler : null;
    const hookedMiddleware = pluginHook('postgraphile:middleware', middleware, {
        options,
    });
    // Sanity check:
    if (!hookedMiddleware.getGraphQLSchema) {
        throw new Error("Hook for 'postgraphile:middleware' has not copied over the helpers; e.g. missing `Object.assign(newMiddleware, oldMiddleware)`");
    }
    return hookedMiddleware;
}
exports.default = createPostGraphileHttpRequestHandler;
/**
 * Adds CORS to a request. See [this][1] flowchart for an explanation of how
 * CORS works. Note that these headers are set for all requests, CORS
 * algorithms normally run a preflight request using the `OPTIONS` method to
 * get these headers.
 *
 * Note though, that enabling CORS will incur extra costs when it comes to the
 * preflight requests. It is much better if you choose to use a proxy and
 * bypass CORS altogether.
 *
 * [1]: http://www.html5rocks.com/static/images/cors_server_flowchart.png
 */
function addCORSHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'HEAD, GET, POST');
    res.setHeader('Access-Control-Allow-Headers', [
        'Origin',
        'X-Requested-With',
        // Used by `express-graphql` to determine whether to expose the GraphiQL
        // interface (`text/html`) or not.
        'Accept',
        // Used by PostGraphile for auth purposes.
        'Authorization',
        // Used by GraphQL Playground and other Apollo-enabled servers
        'X-Apollo-Tracing',
        // The `Content-*` headers are used when making requests with a body,
        // like in a POST request.
        'Content-Type',
        'Content-Length',
        // For our 'Explain' feature
        'X-PostGraphile-Explain',
    ].join(', '));
    res.setHeader('Access-Control-Expose-Headers', ['X-GraphQL-Event-Stream'].join(', '));
}
function createBadAuthorizationHeaderError() {
    return httpError(400, 'Authorization header is not of the correct bearer scheme format.');
}
/**
 * Parses the `Bearer` auth scheme token out of the `Authorization` header as
 * defined by [RFC7235][1].
 *
 * ```
 * Authorization = credentials
 * credentials   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
 * token68       = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" )*"="
 * ```
 *
 * [1]: https://tools.ietf.org/html/rfc7235
 *
 * @private
 */
const authorizationBearerRex = /^\s*bearer\s+([a-z0-9\-._~+/]+=*)\s*$/i;
/**
 * Gets the JWT token from the Http request’s headers. Specifically the
 * `Authorization` header in the `Bearer` format. Will throw an error if the
 * header is in the incorrect format, but will not throw an error if the header
 * does not exist.
 *
 * @private
 * @param {IncomingMessage} request
 * @returns {string | null}
 */
function getJwtToken(request) {
    const { authorization } = request.headers;
    if (Array.isArray(authorization))
        throw createBadAuthorizationHeaderError();
    // If there was no authorization header, just return null.
    if (authorization == null)
        return null;
    const match = authorizationBearerRex.exec(authorization);
    // If we did not match the authorization header with our expected format,
    // throw a 400 error.
    if (!match)
        throw createBadAuthorizationHeaderError();
    // Return the token from our match.
    return match[1];
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3JlYXRlUG9zdEdyYXBoaWxlSHR0cFJlcXVlc3RIYW5kbGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL3Bvc3RncmFwaGlsZS9odHRwL2NyZWF0ZVBvc3RHcmFwaGlsZUh0dHBSZXF1ZXN0SGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSw4RUFBOEU7QUFDOUUscUNBV2lCO0FBQ2pCLGdFQUE2RDtBQUU3RCw4Q0FBc0Q7QUFFdEQsbUVBQTREO0FBQzVELHdFQUFpRTtBQUVqRSx1Q0FBZ0M7QUFFaEMsaUNBQTBCO0FBQzFCLGtDQUFtQyxDQUFDLG9DQUFvQztBQUN4RSx5Q0FBMEM7QUFDMUMscUNBQXNDO0FBQ3RDLDZDQUE4QztBQUM5QywwQ0FBMkM7QUFDM0MsaUNBQWtDO0FBRWxDLE1BQU0sUUFBUSxHQUFHLENBQUMsQ0FBTSxFQUFFLENBQU0sRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUMsR0FBRyxJQUFJLE9BQU8sQ0FBQyxLQUFLLFVBQVUsQ0FBQztBQUUvRSxNQUFNLGdCQUFnQixHQUFHLE1BQU0sQ0FBQztBQUVoQyxNQUFNLHlCQUF5QixHQUFHLDBCQUEwQixDQUFDO0FBQzdELE1BQU0sSUFBSSxHQUFHLEdBQUcsRUFBRTtJQUNoQixVQUFVO0FBQ1osQ0FBQyxDQUFDO0FBRUYsTUFBTSxFQUFFLFVBQVUsRUFBRSxHQUFHLE1BQU0sQ0FBQztBQUU5Qjs7Ozs7R0FLRztBQUNILDBEQUErQztBQUUvQzs7O0dBR0c7QUFDSCw4REFBMEQ7QUFDMUQsbURBQXFFO0FBQ3JFLDZDQUtzQjtBQUV0Qjs7O0dBR0c7QUFDSCxNQUFNLGdCQUFnQixHQUFHO0lBQ3ZCLEdBQUcsRUFBRSxTQUFTO0lBQ2QsR0FBRyxFQUFFLFNBQVM7SUFDZCxHQUFHLEVBQUUsU0FBUztJQUNkLFFBQVEsRUFBRSxTQUFTO0lBQ25CLFFBQVEsRUFBRSxTQUFTO0NBQ3BCLENBQUM7QUFDRixT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