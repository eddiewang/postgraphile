"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.enhanceHttpServerWithSubscriptions = void 0;
const http_1 = require("http");
const graphql_1 = require("graphql");
const WebSocket = require("ws");
const subscriptions_transport_ws_1 = require("subscriptions-transport-ws");
const parseUrl = require("parseurl");
const pluginHook_1 = require("../pluginHook");
const createPostGraphileHttpRequestHandler_1 = require("./createPostGraphileHttpRequestHandler");
const liveSubscribe_1 = require("./liveSubscribe");
function lowerCaseKeys(obj) {
    return Object.keys(obj).reduce((memo, key) => {
        memo[key.toLowerCase()] = obj[key];
        return memo;
    }, {});
}
function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((_resolve, _reject) => {
        resolve = _resolve;
        reject = _reject;
    });
    // tslint:disable-next-line prefer-object-spread
    return Object.assign(promise, {
        // @ts-ignore This isn't used before being defined.
        resolve,
        // @ts-ignore This isn't used before being defined.
        reject,
    });
}
async function enhanceHttpServerWithSubscriptions(websocketServer, postgraphileMiddleware, subscriptionServerOptions) {
    if (websocketServer['__postgraphileSubscriptionsEnabled']) {
        return;
    }
    websocketServer['__postgraphileSubscriptionsEnabled'] = true;
    const { options, getGraphQLSchema, withPostGraphileContextFromReqRes, handleErrors, } = postgraphileMiddleware;
    const pluginHook = pluginHook_1.pluginHookFromOptions(options);
    const graphqlRoute = (subscriptionServerOptions && subscriptionServerOptions.graphqlRoute) ||
        (options.externalUrlBase || '') + (options.graphqlRoute || '/graphql');
    const schema = await getGraphQLSchema();
    const keepalivePromisesByContextKey = {};
    const contextKey = (ws, opId) => ws['postgraphileId'] + '|' + opId;
    const releaseContextForSocketAndOpId = (ws, opId) => {
        const promise = keepalivePromisesByContextKey[contextKey(ws, opId)];
        if (promise) {
            promise.resolve();
            keepalivePromisesByContextKey[contextKey(ws, opId)] = null;
        }
    };
    const addContextForSocketAndOpId = (context, ws, opId) => {
        releaseContextForSocketAndOpId(ws, opId);
        const promise = deferred();
        promise['context'] = context;
        keepalivePromisesByContextKey[contextKey(ws, opId)] = promise;
        return promise;
    };
    const applyMiddleware = async (middlewares = [], req, res) => {
        for (const middleware of middlewares) {
            // TODO: add Koa support
            await new Promise((resolve, reject) => {
                middleware(req, res, err => (err ? reject(err) : resolve()));
            });
        }
    };
    const reqResFromSocket = async (socket) => {
        const req = socket['__postgraphileReq'];
        if (!req) {
            throw new Error('req could not be extracted');
        }
        let dummyRes = socket['__postgraphileRes'];
        if (req.res) {
            throw new Error("Please get in touch with Benjie; we weren't expecting req.res to be present but we want to reserve it for future usage.");
        }
        if (!dummyRes) {
            dummyRes = new http_1.ServerResponse(req);
            dummyRes.writeHead = (statusCode, _statusMessage, headers) => {
                if (statusCode && statusCode > 200) {
                    // tslint:disable-next-line no-console
                    console.error(`Something used 'writeHead' to write a '${statusCode}' error for websockets - check the middleware you're passing!`);
                    socket.close();
                }
                else if (headers) {
                    // tslint:disable-next-line no-console
                    console.error("Passing headers to 'writeHead' is not supported with websockets currently - check the middleware you're passing");
                    socket.close();
                }
            };
            await applyMiddleware(options.websocketMiddlewares, req, dummyRes);
            // reqResFromSocket is only called once per socket, so there's no race condition here
            // eslint-disable-next-line require-atomic-updates
            socket['__postgraphileRes'] = dummyRes;
        }
        return { req, res: dummyRes };
    };
    const getContext = (socket, opId) => {
        return new Promise((resolve, reject) => {
            reqResFromSocket(socket)
                .then(({ req, res }) => withPostGraphileContextFromReqRes(req, res, { singleStatement: true }, context => {
                const promise = addContextForSocketAndOpId(context, socket, opId);
                resolve(promise['context']);
                return promise;
            }))
                .then(null, reject);
        });
    };
    const wss = new WebSocket.Server({ noServer: true });
    let socketId = 0;
    websocketServer.on('upgrade', (req, socket, head) => {
        const { pathname = '' } = parseUrl(req) || {};
        const isGraphqlRoute = pathname === graphqlRoute;
        if (isGraphqlRoute) {
            wss.handleUpgrade(req, socket, head, ws => {
                wss.emit('connection', ws, req);
            });
        }
    });
    const staticValidationRules = pluginHook('postgraphile:validationRules:static', graphql_1.specifiedRules, {
        options,
    });
    subscriptions_transport_ws_1.SubscriptionServer.create(Object.assign({ schema, validationRules: staticValidationRules, execute: () => {
            throw new Error('Only subscriptions are allowed over websocket transport');
        }, subscribe: options.live ? liveSubscribe_1.default : graphql_1.subscribe, onConnect(connectionParams, _socket, connectionContext) {
            const { socket, request } = connectionContext;
            socket['postgraphileId'] = ++socketId;
            if (!request) {
                throw new Error('No request!');
            }
            const normalizedConnectionParams = lowerCaseKeys(connectionParams);
            request['connectionParams'] = connectionParams;
            request['normalizedConnectionParams'] = normalizedConnectionParams;
            socket['__postgraphileReq'] = request;
            if (!request.headers.authorization && normalizedConnectionParams['authorization']) {
                /*
                 * Enable JWT support through connectionParams.
                 *
                 * For other headers you'll need to do this yourself for security
                 * reasons (e.g. we don't want to allow overriding of Origin /
                 * Referer / etc)
                 */
                request.headers.authorization = String(normalizedConnectionParams['authorization']);
            }
            socket['postgraphileHeaders'] = Object.assign(Object.assign({}, normalizedConnectionParams), request.headers);
        },
        // tslint:disable-next-line no-any
        async onOperation(message, params, socket) {
            const opId = message.id;
            const context = await getContext(socket, opId);
            // Override schema (for --watch)
            params.schema = await getGraphQLSchema();
            Object.assign(params.context, context);
            const { req, res } = await reqResFromSocket(socket);
            const meta = {};
            const formatResponse = (response) => {
                if (response.errors) {
                    response.errors = handleErrors(response.errors, req, res);
                }
                if (!createPostGraphileHttpRequestHandler_1.isEmpty(meta)) {
                    response['meta'] = meta;
                }
                return response;
            };
            // onOperation is only called once per params object, so there's no race condition here
            // eslint-disable-next-line require-atomic-updates
            params.formatResponse = formatResponse;
            const hookedParams = pluginHook
                ? pluginHook('postgraphile:ws:onOperation', params, {
                    message,
                    params,
                    socket,
                    options,
                })
                : params;
            const finalParams = Object.assign(Object.assign({}, hookedParams), { query: typeof hookedParams.query !== 'string' ? hookedParams.query : graphql_1.parse(hookedParams.query) });
            // You are strongly encouraged to use
            // `postgraphile:validationRules:static` if possible - you should
            // only use this one if you need access to variables.
            const moreValidationRules = pluginHook('postgraphile:validationRules', [], {
                options,
                req,
                res,
                variables: params.variables,
                operationName: params.operationName,
                meta,
            });
            if (moreValidationRules.length) {
                const validationErrors = graphql_1.validate(params.schema, finalParams.query, moreValidationRules);
                if (validationErrors.length) {
                    const error = new Error('Query validation failed: \n' + validationErrors.map(e => e.message).join('\n'));
                    error['errors'] = validationErrors;
                    return Promise.reject(error);
                }
            }
            return finalParams;
        },
        onOperationComplete(socket, opId) {
            releaseContextForSocketAndOpId(socket, opId);
        }, 
        /*
         * Heroku times out after 55s:
         *   https://devcenter.heroku.com/articles/error-codes#h15-idle-connection
         *
         * The subscriptions-transport-ws client times out by default 30s after last keepalive:
         *   https://github.com/apollographql/subscriptions-transport-ws/blob/52758bfba6190169a28078ecbafd2e457a2ff7a8/src/defaults.ts#L1
         *
         * GraphQL Playground times out after 20s:
         *   https://github.com/prisma/graphql-playground/blob/fa91e1b6d0488e6b5563d8b472682fe728ee0431/packages/graphql-playground-react/src/state/sessions/fetchingSagas.ts#L81
         *
         * Pick a number under these ceilings.
         */
        keepAlive: 15000 }, subscriptionServerOptions), wss);
}
exports.enhanceHttpServerWithSubscriptions = enhanceHttpServerWithSubscriptions;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic3Vic2NyaXB0aW9ucy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9wb3N0Z3JhcGhpbGUvaHR0cC9zdWJzY3JpcHRpb25zLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLCtCQUFvRjtBQUVwRixxQ0FRaUI7QUFDakIsZ0NBQWdDO0FBQ2hDLDJFQUFvRztBQUNwRyxxQ0FBc0M7QUFDdEMsOENBQXNEO0FBQ3RELGlHQUFpRTtBQUNqRSxtREFBNEM7QUFPNUMsU0FBUyxhQUFhLENBQUMsR0FBd0I7SUFDN0MsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksRUFBRSxHQUFHLEVBQUUsRUFBRTtRQUMzQyxJQUFJLENBQUMsR0FBRyxDQUFDLFdBQVcsRUFBRSxDQUFDLEdBQUcsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQ25DLE9BQU8sSUFBSSxDQUFDO0lBQ2QsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDO0FBQ1QsQ0FBQztBQUVELFNBQVMsUUFBUTtJQUNmLElBQUksT0FBeUQsQ0FBQztJQUM5RCxJQUFJLE1BQThCLENBQUM7SUFDbkMsTUFBTSxPQUFPLEdBQUcsSUFBSSxPQUFPLENBQUksQ0FBQyxRQUFRLEVBQUUsT0FBTyxFQUFRLEVBQUU7UUFDekQsT0FBTyxHQUFHLFFBQVEsQ0FBQztRQUNuQixNQUFNLEdBQUcsT0FBTyxDQUFDO0lBQ25CLENBQUMsQ0FBQyxDQUFDO0lBQ0gsZ0RBQWdEO0lBQ2hELE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUU7UUFDNUIsbURBQW1EO1FBQ25ELE9BQU87UUFDUCxtREFBbUQ7UUFDbkQsTUFBTTtLQUNQLENBQUMsQ0FBQztBQUNMLENBQUM7QUFFTSxLQUFLLFVBQVUsa0NBQWtDLENBSXRELGVBQXVCLEVBQ3ZCLHNCQUEwQyxFQUMxQyx5QkFHQztJQUVELElBQUksZUFBZSxDQUFDLG9DQUFvQyxD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