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
    subscriptions_transport_ws_1.SubscriptionServer.create({
        schema,
        validationRules: staticValidationRules,
        execute: () => {
            throw new Error('Only subscriptions are allowed over websocket transport');
        },
        subscribe: options.live ? liveSubscribe_1.default : graphql_1.subscribe,
        onConnect(connectionParams, _socket, connectionContext) {
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
            socket['postgraphileHeaders'] = {
                ...normalizedConnectionParams,
                // The original headers must win (for security)
                ...request.headers,
            };
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
            const finalParams = {
                ...hookedParams,
                query: typeof hookedParams.query !== 'string' ? hookedParams.query : graphql_1.parse(hookedParams.query),
            };
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
        keepAlive: 15000,
        ...subscriptionServerOptions,
    }, wss);
}
exports.enhanceHttpServerWithSubscriptions = enhanceHttpServerWithSubscriptions;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic3Vic2NyaXB0aW9ucy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9wb3N0Z3JhcGhpbGUvaHR0cC9zdWJzY3JpcHRpb25zLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLCtCQUFvRjtBQUVwRixxQ0FRaUI7QUFDakIsZ0NBQWdDO0FBQ2hDLDJFQUFvRztBQUNwRyxxQ0FBc0M7QUFDdEMsOENBQXNEO0FBQ3RELGlHQUFpRTtBQUNqRSxtREFBNEM7QUFPNUMsU0FBUyxhQUFhLENBQUMsR0FBd0I7SUFDN0MsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksRUFBRSxHQUFHLEVBQUUsRUFBRTtRQUMzQyxJQUFJLENBQUMsR0FBRyxDQUFDLFdBQVcsRUFBRSxDQUFDLEdBQUcsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQ25DLE9BQU8sSUFBSSxDQUFDO0lBQ2QsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDO0FBQ1QsQ0FBQztBQUVELFNBQVMsUUFBUTtJQUNmLElBQUksT0FBeUQsQ0FBQztJQUM5RCxJQUFJLE1BQThCLENBQUM7SUFDbkMsTUFBTSxPQUFPLEdBQUcsSUFBSSxPQUFPLENBQUksQ0FBQyxRQUFRLEVBQUUsT0FBTyxFQUFRLEVBQUU7UUFDekQsT0FBTyxHQUFHLFFBQVEsQ0FBQztRQUNuQixNQUFNLEdBQUcsT0FBTyxDQUFDO0lBQ25CLENBQUMsQ0FBQyxDQUFDO0lBQ0gsZ0RBQWdEO0lBQ2hELE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUU7UUFDNUIsbURBQW1EO1FBQ25ELE9BQU87UUFDUCxtREFBbUQ7UUFDbkQsTUFBTTtLQUNQLENBQUMsQ0FBQztBQUNMLENBQUM7QUFFTSxLQUFLLFVBQVUsa0NBQWtDLENBSXRELGVBQXVCLEVBQ3ZCLHNCQUEwQyxFQUMxQyx5QkFHQztJQUVELElBQUksZUFBZSxDQUFDLG9DQUFvQyxDQUFDLEVBQUU7UUFDekQsT0FBTztLQUNSO0lBQ0QsZUFBZSxDQUFDLG9DQUFvQyxDQUFDLEdBQUcsSUFBSSxDQUFDO0lBQzdELE1BQU0sRUFDSixPQUFPLEVBQ1AsZ0JBQWdCLEVBQ2hCLGlDQUFpQyxFQUNqQyxZQUFZLEdBQ2IsR0FBRyxzQkFBc0IsQ0FBQztJQUMzQixNQUFNLFVBQVUsR0FBRyxrQ0FBcUIsQ0FBQyxPQUFPLENBQUMsQ0FBQztJQUNsRCxNQUFNLFlBQVksR0FDaEIsQ0FBQyx5QkFBeUIsSUFBSSx5QkFBeUIsQ0FBQyxZQUFZLENBQUM7UUFDckUsQ0FBQyxPQUFPLENBQUMsZUFBZSxJQUFJLEVBQUUsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFlBQVksSUFBSSxVQUFVLENBQUMsQ0FBQztJQUV6RSxNQUFNLE1BQU0sR0FBRyxNQUFNLGdCQUFnQixFQUFFLENBQUM7SUFFeEMsTUFBTSw2QkFBNkIsR0FBb0QsRUFBRSxDQUFDO0lBRTFGLE1BQU0sVUFBVSxHQUFHLENBQUMsRUFBYSxFQUFFLElBQVksRUFBVSxFQUFFLENBQUMsRUFBRSxDQUFDLGdCQUFnQixDQUFDLEdBQUcsR0FBRyxHQUFHLElBQUksQ0FBQztJQUU5RixNQUFNLDhCQUE4QixHQUFHLENBQUMsRUFBYSxFQUFFLElBQVksRUFBUSxFQUFFO1FBQzNFLE1BQU0sT0FBTyxHQUFHLDZCQUE2QixDQUFDLFVBQVUsQ0FBQyxFQUFFLEVBQUUsSUFBSSxDQUFDLENBQUMsQ0FBQztRQUNwRSxJQUFJLE9BQU8sRUFBRTtZQUNYLE9BQU8sQ0FBQyxPQUFPLEVBQUUsQ0FBQztZQUNsQiw2QkFBNkIsQ0FBQyxVQUFVLENBQUMsRUFBRSxFQUFFLElBQUksQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDO1NBQzVEO0lBQ0gsQ0FBQyxDQUFDO0lBRUYsTUFBTSwwQkFBMEIsR0FBRyxDQUNqQyxPQUFjLEVBQ2QsRUFBYSxFQUNiLElBQVksRUFDSSxFQUFFO1FBQ2xCLDhCQUE4QixDQUFDLEVBQUUsRUFBRSxJQUFJLENBQUMsQ0FBQztRQUN6QyxNQUFNLE9BQU8sR0FBRyxRQUFRLEVBQUUsQ0FBQztRQUMzQixPQUFPLENBQUMsU0FBUyxDQUFDLEdBQUcsT0FBTyxDQUFDO1FBQzdCLDZCQUE2QixDQUFDLFVBQVUsQ0FBQyxFQUFFLEVBQUUsSUFBSSxDQUFDLENBQUMsR0FBRyxPQUFPLENBQUM7UUFDOUQsT0FBTyxPQUFPLENBQUM7SUFDakIsQ0FBQyxDQUFDO0lBRUYsTUFBTSxlQUFlLEdBQUcsS0FBSyxFQUMzQixjQUFvRCxFQUFFLEVBQ3RELEdBQVksRUFDWixHQUFhLEVBQ0UsRUFBRTtRQUNqQixLQUFLLE1BQU0sVUFBVSxJQUFJLFdBQVcsRUFBRTtZQUNwQyx3QkFBd0I7WUFDeEIsTUFBTSxJQUFJLE9BQU8sQ0FBQyxDQUFDLE9BQU8sRUFBRSxNQUFNLEVBQVEsRUFBRTtnQkFDMUMsVUFBVSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxDQUFDLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLEVBQUUsQ0FBQyxDQUFDLENBQUM7WUFDL0QsQ0FBQyxDQUFDLENBQUM7U0FDSjtJQUNILENBQUMsQ0FBQztJQUVGLE1BQU0sZ0JBQWdCLEdBQUcsS0FBSyxFQUM1QixNQUFpQixFQUloQixFQUFFO1FBQ0gsTUFBTSxHQUFHLEdBQUcsTUFBTSxDQUFDLG1CQUFtQixDQUFDLENBQUM7UUFDeEMsSUFBSSxDQUFDLEdBQUcsRUFBRTtZQUNSLE1BQU0sSUFBSSxLQUFLLENBQUMsNEJBQTRCLENBQUMsQ0FBQztTQUMvQztRQUNELElBQUksUUFBUSxHQUF5QixNQUFNLENBQUMsbUJBQW1CLENBQUMsQ0FBQztRQUNqRSxJQUFJLEdBQUcsQ0FBQyxHQUFHLEVBQUU7WUFDWCxNQUFNLElBQUksS0FBSyxDQUNiLHlIQUF5SCxDQUMxSCxDQUFDO1NBQ0g7UUFDRCxJQUFJLENBQUMsUUFBUSxFQUFFO1lBQ2IsUUFBUSxHQUFHLElBQUkscUJBQWMsQ0FBQyxHQUFHLENBQWEsQ0FBQztZQUMvQyxRQUFRLENBQUMsU0FBUyxHQUFHLENBQ25CLFVBQWtCLEVBQ2xCLGNBQXlELEVBQ3pELE9BQXlDLEVBQ25DLEVBQUU7Z0JBQ1IsSUFBSSxVQUFVLElBQUksVUFBVSxHQUFHLEdBQUcsRUFBRTtvQkFDbEMsc0NBQXNDO29CQUN0QyxPQUFPLENBQUMsS0FBSyxDQUNYLDBDQUEwQyxVQUFVLCtEQUErRCxDQUNwSCxDQUFDO29CQUNGLE1BQU0sQ0FBQyxLQUFLLEVBQUUsQ0FBQztpQkFDaEI7cUJBQU0sSUFBSSxPQUFPLEVBQUU7b0JBQ2xCLHNDQUFzQztvQkFDdEMsT0FBTyxDQUFDLEtBQUssQ0FDWCxpSEFBaUgsQ0FDbEgsQ0FBQztvQkFDRixNQUFNLENBQUMsS0FBSyxFQUFFLENBQUM7aUJBQ2hCO1lBQ0gsQ0FBQyxDQUFDO1lBQ0YsTUFBTSxlQUFlLENBQUMsT0FBTyxDQUFDLG9CQUFvQixFQUFFLEdBQUcsRUFBRSxRQUFRLENBQUMsQ0FBQztZQUVuRSxxRkFBcUY7WUFDckYsa0RBQWtEO1lBQ2xELE1BQU0sQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLFFBQVEsQ0FBQztTQUN4QztRQUNELE9BQU8sRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLFFBQVEsRUFBRSxDQUFDO0lBQ2hDLENBQUMsQ0FBQztJQUVGLE1BQU0sVUFBVSxHQUFHLENBQUMsTUFBaUIsRUFBRSxJQUFZLEVBQWtCLEVBQUU7UUFDckUsT0FBTyxJQUFJLE9BQU8sQ0FBQyxDQUFDLE9BQU8sRUFBRSxNQUFNLEVBQVEsRUFBRTtZQUMzQyxnQkFBZ0IsQ0FBQyxNQUFNLENBQUM7aUJBQ3JCLElBQUksQ0FBQyxDQUFDLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFLEVBQUUsQ0FDckIsaUNBQWlDLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxFQUFFLGVBQWUsRUFBRSxJQUFJLEVBQUUsRUFBRSxPQUFPLENBQUMsRUFBRTtnQkFDL0UsTUFBTSxPQUFPLEdBQUcsMEJBQTBCLENBQUMsT0FBTyxFQUFFLE1BQU0sRUFBRSxJQUFJLENBQUMsQ0FBQztnQkFDbEUsT0FBTyxDQUFDLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQyxDQUFDO2dCQUM1QixPQUFPLE9BQU8sQ0FBQztZQUNqQixDQUFDLENBQUMsQ0FDSDtpQkFDQSxJQUFJLENBQUMsSUFBSSxFQUFFLE1BQU0sQ0FBQyxDQUFDO1FBQ3hCLENBQUMsQ0FBQyxDQUFDO0lBQ0wsQ0FBQyxDQUFDO0lBRUYsTUFBTSxHQUFHLEdBQUcsSUFBSSxTQUFTLENBQUMsTUFBTSxDQUFDLEVBQUUsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7SUFFckQsSUFBSSxRQUFRLEdBQUcsQ0FBQyxDQUFDO0lBRWpCLGVBQWUsQ0FBQyxFQUFFLENBQUMsU0FBUyxFQUFFLENBQUMsR0FBRyxFQUFFLE1BQU0sRUFBRSxJQUFJLEVBQUUsRUFBRTtRQUNsRCxNQUFNLEVBQUUsUUFBUSxHQUFHLEVBQUUsRUFBRSxHQUFHLFFBQVEsQ0FBQyxHQUFHLENBQUMsSUFBSSxFQUFFLENBQUM7UUFDOUMsTUFBTSxjQUFjLEdBQUcsUUFBUSxLQUFLLFlBQVksQ0FBQztRQUNqRCxJQUFJLGNBQWMsRUFBRTtZQUNsQixHQUFHLENBQUMsYUFBYSxDQUFDLEdBQUcsRUFBRSxNQUFNLEVBQUUsSUFBSSxFQUFFLEVBQUUsQ0FBQyxFQUFFO2dCQUN4QyxHQUFHLENBQUMsSUFBSSxDQUFDLFlBQVksRUFBRSxFQUFFLEVBQUUsR0FBRyxDQUFDLENBQUM7WUFDbEMsQ0FBQyxDQUFDLENBQUM7U0FDSjtJQUNILENBQUMsQ0FBQyxDQUFDO0lBQ0gsTUFBTSxxQkFBcUIsR0FBRyxVQUFVLENBQUMscUNBQXFDLEVBQUUsd0JBQWMsRUFBRTtRQUM5RixPQUFPO0tBQ1IsQ0FBQyxDQUFDO0lBRUgsK0NBQWtCLENBQUMsTUFBTSxDQUN2QjtRQUNFLE1BQU07UUFDTixlQUFlLEVBQUUscUJBQXFCO1FBQ3RDLE9BQU8sRUFBRSxHQUFHLEVBQUU7WUFDWixNQUFNLElBQUksS0FBSyxDQUFDLHlEQUF5RCxDQUFDLENBQUM7UUFDN0UsQ0FBQztRQUNELFNBQVMsRUFBRSxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyx1QkFBYSxDQUFDLENBQUMsQ0FBQyxtQkFBZ0I7UUFDMUQsU0FBUyxDQUNQLGdCQUFxQyxFQUNyQyxPQUFrQixFQUNsQixpQkFBb0M7WUFFcEMsTUFBTSxFQUFFLE1BQU0sRUFBRSxPQUFPLEVBQUUsR0FBRyxpQkFBaUIsQ0FBQztZQUM5QyxNQUFNLENBQUMsZ0JBQWdCLENBQUMsR0FBRyxFQUFFLFFBQVEsQ0FBQztZQUN0QyxJQUFJLENBQUMsT0FBTyxFQUFFO2dCQUNaLE1BQU0sSUFBSSxLQUFLLENBQUMsYUFBYSxDQUFDLENBQUM7YUFDaEM7WUFDRCxNQUFNLDBCQUEwQixHQUFHLGFBQWEsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO1lBQ25FLE9BQU8sQ0FBQyxrQkFBa0IsQ0FBQyxHQUFHLGdCQUFnQixDQUFDO1lBQy9DLE9BQU8sQ0FBQyw0QkFBNEIsQ0FBQyxHQUFHLDBCQUEwQixDQUFDO1lBQ25FLE1BQU0sQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLE9BQU8sQ0FBQztZQUN0QyxJQUFJLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxhQUFhLElBQUksMEJBQTBCLENBQUMsZUFBZSxDQUFDLEVBQUU7Z0JBQ2pGOzs7Ozs7bUJBTUc7Z0JBQ0gsT0FBTyxDQUFDLE9BQU8sQ0FBQyxhQUFhLEdBQUcsTUFBTSxDQUFDLDBCQUEwQixDQUFDLGVBQWUsQ0FBQyxDQUFDLENBQUM7YUFDckY7WUFFRCxNQUFNLENBQUMscUJBQXFCLENBQUMsR0FBRztnQkFDOUIsR0FBRywwQkFBMEI7Z0JBQzdCLCtDQUErQztnQkFDL0MsR0FBRyxPQUFPLENBQUMsT0FBTzthQUNuQixDQUFDO1FBQ0osQ0FBQztRQUNELGtDQUFrQztRQUNsQyxLQUFLLENBQUMsV0FBVyxDQUFDLE9BQVksRUFBRSxNQUF1QixFQUFFLE1BQWlCO1lBQ3hFLE1BQU0sSUFBSSxHQUFHLE9BQU8sQ0FBQyxFQUFFLENBQUM7WUFDeEIsTUFBTSxPQUFPLEdBQUcsTUFBTSxVQUFVLENBQUMsTUFBTSxFQUFFLElBQUksQ0FBQyxDQUFDO1lBRS9DLGdDQUFnQztZQUNoQyxNQUFNLENBQUMsTUFBTSxHQUFHLE1BQU0sZ0JBQWdCLEVBQUUsQ0FBQztZQUV6QyxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUM7WUFFdkMsTUFBTSxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxNQUFNLGdCQUFnQixDQUFDLE1BQU0sQ0FBQyxDQUFDO1lBQ3BELE1BQU0sSUFBSSxHQUFHLEVBQUUsQ0FBQztZQUNoQixNQUFNLGNBQWMsR0FBRyxDQUNyQixRQUEwQixFQUNSLEVBQUU7Z0JBQ3BCLElBQUksUUFBUSxDQUFDLE1BQU0sRUFBRTtvQkFDbkIsUUFBUSxDQUFDLE1BQU0sR0FBRyxZQUFZLENBQUMsUUFBUSxDQUFDLE1BQU0sRUFBRSxHQUFHLEVBQUUsR0FBRyxDQUFDLENBQUM7aUJBQzNEO2dCQUNELElBQUksQ0FBQyw4Q0FBTyxDQUFDLElBQUksQ0FBQyxFQUFFO29CQUNsQixRQUFRLENBQUMsTUFBTSxDQUFDLEdBQUcsSUFBSSxDQUFDO2lCQUN6QjtnQkFFRCxPQUFPLFFBQVEsQ0FBQztZQUNsQixDQUFDLENBQUM7WUFDRix1RkFBdUY7WUFDdkYsa0RBQWtEO1lBQ2xELE1BQU0sQ0FBQyxjQUFjLEdBQUcsY0FBYyxDQUFDO1lBQ3ZDLE1BQU0sWUFBWSxHQUFHLFVBQVU7Z0JBQzdCLENBQUMsQ0FBQyxVQUFVLENBQUMsNkJBQTZCLEVBQUUsTUFBTSxFQUFFO29CQUNoRCxPQUFPO29CQUNQLE1BQU07b0JBQ04sTUFBTTtvQkFDTixPQUFPO2lCQUNSLENBQUM7Z0JBQ0osQ0FBQyxDQUFDLE1BQU0sQ0FBQztZQUNYLE1BQU0sV0FBVyxHQUFrRDtnQkFDakUsR0FBRyxZQUFZO2dCQUNmLEtBQUssRUFDSCxPQUFPLFlBQVksQ0FBQyxLQUFLLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQyxZQUFZLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxlQUFLLENBQUMsWUFBWSxDQUFDLEtBQUssQ0FBQzthQUMxRixDQUFDO1lBRUYscUNBQXFDO1lBQ3JDLGlFQUFpRTtZQUNqRSxxREFBcUQ7WUFDckQsTUFBTSxtQkFBbUIsR0FBRyxVQUFVLENBQUMsOEJBQThCLEVBQUUsRUFBRSxFQUFFO2dCQUN6RSxPQUFPO2dCQUNQLEdBQUc7Z0JBQ0gsR0FBRztnQkFDSCxTQUFTLEVBQUUsTUFBTSxDQUFDLFNBQVM7Z0JBQzNCLGFBQWEsRUFBRSxNQUFNLENBQUMsYUFBYTtnQkFDbkMsSUFBSTthQUNMLENBQUMsQ0FBQztZQUNILElBQUksbUJBQW1CLENBQUMsTUFBTSxFQUFFO2dCQUM5QixNQUFNLGdCQUFnQixHQUFnQyxrQkFBUSxDQUM1RCxNQUFNLENBQUMsTUFBTSxFQUNiLFdBQVcsQ0FBQyxLQUFLLEVBQ2pCLG1CQUFtQixDQUNwQixDQUFDO2dCQUNGLElBQUksZ0JBQWdCLENBQUMsTUFBTSxFQUFFO29CQUMzQixNQUFNLEtBQUssR0FBRyxJQUFJLEtBQUssQ0FDckIsNkJBQTZCLEdBQUcsZ0JBQWdCLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FDaEYsQ0FBQztvQkFDRixLQUFLLENBQUMsUUFBUSxDQUFDLEdBQUcsZ0JBQWdCLENBQUM7b0JBQ25DLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQztpQkFDOUI7YUFDRjtZQUVELE9BQU8sV0FBVyxDQUFDO1FBQ3JCLENBQUM7UUFDRCxtQkFBbUIsQ0FBQyxNQUFpQixFQUFFLElBQVk7WUFDakQsOEJBQThCLENBQUMsTUFBTSxFQUFFLElBQUksQ0FBQyxDQUFDO1FBQy9DLENBQUM7UUFFRDs7Ozs7Ozs7Ozs7V0FXRztRQUNILFNBQVMsRUFBRSxLQUFLO1FBRWhCLEdBQUcseUJBQXlCO0tBQzdCLEVBQ0QsR0FBRyxDQUNKLENBQUM7QUFDSixDQUFDO0FBaFJELGdGQWdSQyJ9