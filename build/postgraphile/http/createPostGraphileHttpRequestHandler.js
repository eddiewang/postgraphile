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
        return withPostGraphileContext_1.default(Object.assign(Object.assign(Object.assign({}, options), { jwtToken,
            pgSettings, explain: allowExplain && req.headers['x-postgraphile-explain'] === 'on' }), moreOptions), context => {
            const graphqlContext = additionalContext
                ? Object.assign(Object.assign({}, additionalContext), context) : context;
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
                                return Promise.resolve(graphqlResult).then(async (obj) => (Object.assign(Object.assign({}, obj), { 
                                    // Add our explain data
                                    explain: await graphqlContext.getExplainResults() })));
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