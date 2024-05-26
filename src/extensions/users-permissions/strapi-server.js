const utils = require('@strapi/utils')
const { getService } = require('../users-permissions/utils')
const jwt = require('jsonwebtoken')
const _ = require('lodash')
const {
  validateCallbackBody
} = require('../users-permissions/controllers/validation/auth')

const { sanitize } = utils
const { ApplicationError, ValidationError } = utils.errors

const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state
  const userSchema = strapi.getModel('plugin::users-permissions.user')
  return sanitize.contentAPI.output(user, userSchema, { auth })
}

// issue a JWT
const issueJWT = (payload, jwtOptions = {}) => {
  _.defaults(jwtOptions, strapi.config.get('plugin.users-permissions.jwt'))
  return jwt.sign(
    _.clone(payload.toJSON ? payload.toJSON() : payload),
    strapi.config.get('plugin.users-permissions.jwtSecret'),
    jwtOptions
  )
}

// verify the refreshToken by using the REFRESH_SECRET from the .env
const verifyRefreshToken = (token) => {
  return new Promise(function (resolve, reject) {
    jwt.verify(
      token,
      process.env.REFRESH_SECRET,
      {},
      function (err, tokenPayload = {}) {
        if (err) {
          return reject(new Error('Invalid token.'))
        }
        resolve(tokenPayload)
      }
    )
  })
}

// issue a Refresh token
const issueRefreshToken = (payload, jwtOptions = {}) => {
  _.defaults(jwtOptions, strapi.config.get('plugin.users-permissions.jwt'))
  return jwt.sign(
    _.clone(payload.toJSON ? payload.toJSON() : payload),
    process.env.REFRESH_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES }
  )
}

module.exports = (plugin) => {
  plugin.controllers.auth.callback = async (ctx) => {
    const provider = ctx.params.provider || 'local'
    const params = ctx.request.body
    const store = strapi.store({ type: 'plugin', name: 'users-permissions' })
    const grantSettings = await store.get({ key: 'grant' })
    const grantProvider = provider === 'local' ? 'email' : provider
    if (!_.get(grantSettings, [grantProvider, 'enabled'])) {
      throw new ApplicationError('This provider is disabled')
    }
    if (provider === 'local') {
      await validateCallbackBody(params)
      const { identifier } = params
      // Check if the user exists.
      const user = await strapi
        .query('plugin::users-permissions.user')
        .findOne({
          where: {
            provider,
            $or: [{ email: identifier.toLowerCase() }, { username: identifier }]
          }
        })
      if (!user) {
        throw new ValidationError('Invalid identifier or password')
      }
      if (!user.password) {
        throw new ValidationError('Invalid identifier or password')
      }
      const validPassword = await getService('user').validatePassword(
        params.password,
        user.password
      )
      if (!validPassword) {
        throw new ValidationError('Invalid identifier or password')
      } else {
        ctx.cookies.set('refreshToken', issueRefreshToken({ id: user.id }), {
          httpOnly: true,
          secure: false,
          signed: true,
          overwrite: true
        })
        ctx.send({
          status: 'Authenticated',
          jwt: issueJWT(
            { id: user.id },
            { expiresIn: process.env.JWT_SECRET_EXPIRES }
          ),
          user: await sanitizeUser(user, ctx)
        })
      }
      const advancedSettings = await store.get({ key: 'advanced' })
      const requiresConfirmation = _.get(advancedSettings, 'email_confirmation')
      if (requiresConfirmation && user.confirmed !== true) {
        throw new ApplicationError('Your account email is not confirmed')
      }
      if (user.blocked === true) {
        throw new ApplicationError(
          'Your account has been blocked by an administrator'
        )
      }
      return ctx.send({
        jwt: getService('jwt').issue({ id: user.id }),
        user: await sanitizeUser(user, ctx)
      })
    }
    // Connect the user with a third-party provider.
    try {
      const user = await getService('providers').connect(provider, ctx.query)
      return ctx.send({
        jwt: getService('jwt').issue({ id: user.id }),
        user: await sanitizeUser(user, ctx)
      })
    } catch (error) {
      throw new ApplicationError(error.message)
    }
  }

  plugin.controllers.auth['refreshToken'] = async (ctx) => {
    const store = await strapi.store({
      type: 'plugin',
      name: 'users-permissions'
    })
    let refreshToken = ctx.request.body.refreshToken

    if (!refreshToken) {
      return ctx.badRequest('No Authorization')
    }
    try {
      const obj = await verifyRefreshToken(ctx.request.body.refreshToken)
      const user = await strapi
        .query('plugin::users-permissions.user')
        .findOne({ where: { id: obj.id } })
      if (!user) {
        throw new ValidationError('Invalid identifier or password')
      }
      if (
        _.get(await store.get({ key: 'advanced' }), 'email_confirmation') &&
        user.confirmed !== true
      ) {
        throw new ApplicationError('Your account email is not confirmed')
      }
      if (user.blocked === true) {
        throw new ApplicationError(
          'Your account has been blocked by an administrator'
        )
      }
      const refreshToken = issueRefreshToken({ id: user.id })
      ctx.cookies.set('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,
        signed: true,
        overwrite: true
      })
      ctx.send({
        jwt: issueJWT(
          { id: obj.id },
          { expiresIn: process.env.JWT_SECRET_EXPIRES }
        ),
        refreshToken: refreshToken
      })
    } catch (err) {
      return ctx.badRequest(err.toString())
    }
  }

  plugin.controllers.auth['register'] = async (ctx) => {
    const pluginStore = await strapi.store({
      type: 'plugin',
      name: 'users-permissions'
    })

    const settings = await pluginStore.get({
      key: 'advanced'
    })

    const params = {
      ...ctx.request.body,
      provider: 'local'
    }

    if (!params.password) {
      throw new ApplicationError('Password is required')
    }

    const role = await strapi
      .query('plugin::users-permissions.role')
      .findOne({ where: { type: settings.default_role } })

    if (!role) {
      throw new ApplicationError('Impossible to find the default role')
    }

    params.role = role.id
    params.email = params.email.toLowerCase()

    const userWithSameEmail = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { email: params.email } })

    if (userWithSameEmail) {
      throw new ApplicationError('Email is already taken')
    }

    params.confirmed = !settings.email_confirmation

    const user =
      await strapi.plugins['users-permissions'].services.user.add(params)

    if (settings.email_confirmation) {
      try {
        await strapi.plugins[
          'users-permissions'
        ].services.user.sendConfirmationEmail(user)
      } catch (err) {
        throw new ApplicationError(err.message)
      }
      ctx.send({
        user: await sanitizeUser(user, ctx)
      })
    } else {
      const jwt = issueJWT(
        { id: user.id },
        { expiresIn: process.env.JWT_SECRET_EXPIRES }
      )
      const refreshToken = issueRefreshToken({ id: user.id })

      ctx.cookies.set('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,
        signed: true,
        overwrite: true
      })

      ctx.send({
        jwt,
        refreshToken,
        user: await sanitizeUser(user, ctx)
      })
    }
  }

  plugin.routes['content-api'].routes.push({
    method: 'POST',
    path: '/token/refresh',
    handler: 'auth.refreshToken',
    config: {
      policies: [],
      prefix: '',
      auth: false
    }
  })

  return plugin
}
