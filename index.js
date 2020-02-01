const fs = require('fs');
const path = require('path');
const http = require('http');
const Koa = require('koa');
const cors = require('koa-cors');
const aes = require('crypto-js/aes');
const cryptoEncBase64 = require('crypto-js/enc-base64');
const cryptoEncUtf8 = require('crypto-js/enc-utf8');
const PathMatch = require('path-match');
const staticCache = require('koa-static-cache');
const httpProxy = require('http-proxy');

const loggerFactory = require('logger-factory');

const debug = loggerFactory('spa-server');
const debugProxy = loggerFactory('spa-server:proxy');

var proxy = httpProxy.createServer();

class SpaServer {
  constructor() {
  }

  setDebug(loggerConfig) {
    loggerFactory.getState().setConfigs(loggerConfig);
  }

  // 跨域配置
  setCors(app) {
    app.use(cors({
      allowMethods: ['GET', 'PUT', 'POST', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
    }));
  }

  // 捕获异常
  setLogger(app) {
    // catch error in outer middleware
    app.use(async (ctx, next) => {
      const start = Date.now();
      // debug('<--', ctx.method, ctx.url);

      const res = ctx.res;

      const onfinish = done.bind(null, 'finish');
      const onclose = done.bind(null, 'close');

      res.once('finish', onfinish)
      res.once('close', onclose)

      function done (event) {
        res.removeListener('finish', onfinish);
        res.removeListener('close', onclose);
        debug('-->', ctx.method, ctx.url, ctx.status, `[${Date.now() - start}ms]`)
        // log(print, ctx, start, counter ? counter.length : length, null, event)
      }

      // await next();
      try {
        await next();
      } catch (err) {
        debug(err);
        throw err;
      }
    });
  }

  // 健康检查配置
  setHealthCheck(app, config) {
    if (!config.healthCheck) {
      return;
    }
    app.use(async(ctx, next) => {
      if (['/health', '/healthcheck', '/health-check'].includes(ctx.url.toLowerCase())) {
        ctx.status = 200;
        ctx.body = 'server aliving';
      } else {
        await next();
      }
    });
  }

  /**
   * Koa Http Proxy Middleware
   */
  proxyMiddleware (matchPath, config) {
    const pathMatch = PathMatch({
      // path-to-regexp options
      sensitive: false,
      strict: false,
      end: false,
    })(matchPath);
    return async(ctx, next) => {
      if (!config.hasOwnProperty('target') || !config.hasOwnProperty('changeOrigin')) {
        return await next();
      }

      const {
        target,
        changeOrigin,
        pathRewrite
      } = config;
      // whether request.url match matchPath
      const matchResults = pathMatch(ctx.url);
      if (!matchResults) {
        return await next();
      }

      let start = Date.now();

      var [realName, userName, token] = [];
      try {
        var authOK = true;
        const reqHeaders = ctx.req.headers;
        var decrypted = '';
        if (reqHeaders.hasOwnProperty('auth') && reqHeaders.hasOwnProperty('token')) {
          decrypted = aes.decrypt(reqHeaders['auth'], 'paas').toString(cryptoEncUtf8);
          if (!decrypted) {
            authOK = false;
          } else {
            [realName, userName, token] = decrypted.split(':');
            // decrypted = JSON.parse(decrypted);
            if (token != reqHeaders['token']) {
              authOK = false
            }
          }
        } else if (reqHeaders.hasOwnProperty('auth') || reqHeaders.hasOwnProperty('token')) {
          authOK = false;
        }
        if (!authOK) {
          debugProxy(ctx.req.url);
          debugProxy(reqHeaders);
          debugProxy(decrypted);
          // ctx.assert(false, 200, JSON.stringify({
          //   success: false,
          //   code: 1,
          //   msg: 'proxy: 认证失败',
          //   content: '',
          //   t: new Date().getTime()
          // }));
        }
      } catch (err) {
        console.log(err);
      }

      return new Promise((resolve, reject) => {
        ctx.req.oldPath = ctx.req.url;

        if (typeof pathRewrite === 'function') {
          ctx.req.url = pathRewrite(ctx.req.url, matchResults);
        }

        proxy.web(ctx.req, ctx.res, {
          target, changeOrigin
        }, err => {
          const status = {
            ECONNREFUSED: 503,
            ETIMEOUT: 504,
          }[err.code];
          if (status) {
            ctx.status = status;
          }
          debug(err);
          ctx.respond = false;
          reject(err);
          // resolve();
        });
        proxy.once('end', () => {
          let duration = Date.now() - start;
          debugProxy(realName ? `(${realName})` : '', ctx.req.method, ctx.req.oldPath, 'to', target + ctx.req.url, `[${duration}ms]`);
          ctx.respond = false;
          resolve();
        })
      });
    }
  }

  // 配置代理
  setProxy(app, config) {
    if (!config.proxy) {
      return;
    }
    for (let key in config.proxy) {
      app.use(this.proxyMiddleware(key, config.proxy[key]));
    }
  }

  // 路径重定向
  setRewrite(app, config) {
    if (!config.historyApiFallback) {
      return;
    }
    const middleware = require('connect-history-api-fallback')(config.historyApiFallback);
    app.use((ctx, next) => {
      middleware(ctx, null, () => {});
      return next();
    });
  }

  // 配置静态服务
  setStatic(app, config) {
    if (!config.staticConfig) {
      return;
    }
    const addStatic = (dirOrOptions) => {
      const defaultOptions = {
        gzip: true,
        preload: true,
        buffer: false,
        dynamic: true,
        filter: function(filePath) {
          return !/^node_modules\/.*$/.test(filePath);
        }
      };

      var options = {};
      if (dirOrOptions !== null && typeof dirOrOptions === 'object') {
        options = Object.assign(defaultOptions, dirOrOptions);
      } else {
        options = Object.assign(defaultOptions, {
          dir: dirOrOptions
        });
      }
      if (!fs.existsSync(options.dir)) {
        debug(`WARNING: dir ${options.dir} not exist`);
        return;
      }
      app.use(staticCache(options));
    };
    if (Array.isArray(config.staticConfig)) {
      config.staticConfig.forEach(addStatic);
    } else {
      addStatic(config.staticConfig);
    }
  }

  start(config) {
    this.setDebug(config.logger);
    // debug should call after loggerFactory is set
    debug(config);

    const app = new Koa();
    this.setCors(app);
    this.setLogger(app, config);
    this.setHealthCheck(app, config);
    this.setProxy(app, config);
    // NOTICE: the sequence of koa middleware can not change
    this.setStatic(app, config);
    this.setRewrite(app, config);
    this.setStatic(app, config);

    app.listen(config.port);
    debug(`服务已启动：http://${config.host}:${config.port}`);
  }
}

module.exports = SpaServer;
