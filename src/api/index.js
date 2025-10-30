import hapi from '@hapi/hapi'
import CatboxMemory from '@hapi/catbox-memory'
import Boom from '@hapi/boom'

import { config } from '~/src/config/index.js'
import { router } from '~/src/api/router.js'
import { requestLogger } from '~/src/api/common/helpers/logging/request-logger.js'
import { failAction } from '~/src/api/common/helpers/fail-action.js'
import { secureContext } from '~/src/api/common/helpers/secure-context/index.js'
import { pulse } from '~/src/api/common/helpers/pulse.js'
import { requestTracing } from '~/src/api/common/helpers/request-tracing.js'
import { setupProxy } from '~/src/api/common/helpers/proxy/setup-proxy.js'
import { mongooseDb } from '~/src/api/common/helpers/mongoose.js'
import { errorHandlerPlugin } from '~/src/api/common/helpers/error-handler.js'
import { validateJwtAuthentication } from '~/src/api/common/helpers/jwt-auth.js'
import {
  getAgreementDataById,
  getAgreementDataBySbi
} from './agreement/helpers/get-agreement-data.js'
import { createSqsClientPlugin } from '~/src/api/common/helpers/sqs-client.js'
import { handleCreateAgreementEvent } from './common/helpers/sqs-message-processor/create-agreement.js'
import { handleUpdateAgreementEvent } from './common/helpers/sqs-message-processor/update-agreement.js'
import { returnDataHandlerPlugin } from './common/helpers/return-data-handler.js'
// import { logger } from 'sqs-consumer/src/logger.js'

const customGrantsUiJwtScheme = () => ({
  authenticate: async (request, h) => {
    const { agreementId } = request.params

    // 1) Fetch agreement data by id when provided
    let agreementData = null
    if (agreementId) {
      agreementData = await getAgreementDataById(agreementId)
    }

    const isJwtEnabled = config.get('featureFlags.isJwtEnabled')

    if (!agreementData && !isJwtEnabled) {
      throw Boom.badRequest(
        'Bad request, Neither JWT is enabled nor agreementId is provided'
      )
    }

    let source = null
    let showAgreement = false
    if (isJwtEnabled) {
      const authToken = request.headers['x-encrypted-auth']

      if (!authToken) {
        throw Boom.badRequest(
          'Bad request, JWT is enabled but no auth token provided in the header'
        )
      }

      const authResult = validateJwtAuthentication(
        authToken,
        agreementData,
        request.logger
      )

      request.logger.info(
        `JWT Authentication Validation Start: ${JSON.stringify({
          isJwtEnabled,
          hasAuthToken: !!authToken,
          authTokenLength: authToken ? authToken.length : 0,
          agreementSbi: agreementData?.identifiers?.sbi,
          agreementNumber: agreementData?.agreementNumber
        })}`
      )

      // 3) If validation failed (falsy or valid:false) -> 401
      if (!authResult || authResult.valid === false) {
        throw Boom.unauthorized(
          'Not authorized to view/accept offer agreement document'
        )
      }

      // 4) If no agreement id was supplied but DEFRA farmer JWT contains an SBI, fetch by SBI
      if (!agreementData && checkAuthSourceAndSbi(authResult)) {
        agreementData = await getAgreementDataBySbi(authResult.sbi)
      }

      source = authResult.source
      showAgreement = Boolean(authResult.valid)
    } else {
      request.logger.warn('JWT authentication is disabled via feature flag')
    }

    return h.authenticated({
      credentials: {
        agreementData,
        source,
        showAgreement
      }
    })
  }
})

function checkAuthSourceAndSbi(auth) {
  return typeof auth.source === 'string' && auth.source === 'defra' && auth.sbi
}

async function createServer(serverOptions = {}) {
  setupProxy()
  const server = hapi.server({
    port: config.get('port'),
    routes: {
      validate: {
        options: {
          abortEarly: false
        },
        failAction
      },
      security: {
        hsts: {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: false
        },
        xss: 'enabled',
        noSniff: true,
        xframe: true
      }
    },
    router: {
      stripTrailingSlash: true
    },
    cache: [
      {
        name: 'agreement-service',
        provider: {
          constructor: CatboxMemory.Engine
        }
      }
    ]
  })

  server.auth.scheme('custom-grants-ui-jwt', customGrantsUiJwtScheme)
  server.auth.strategy('grants-ui-jwt', 'custom-grants-ui-jwt')

  const options = {
    disableSQS: false,
    ...serverOptions
  }

  // Hapi Plugins:
  // requestLogger      - automatically logs incoming requests
  // requestTracing     - trace header logging and propagation
  // secureContext      - loads CA certificates from environment config
  // pulse              - provides shutdown handlers
  // mongooseDb         - sets up mongoose connection pool and attaches to `server` and `request` objects
  // sqsClientPlugin    - AWS SQS client
  // errorHandlerPlugin - sets up default error handling
  // router             - routes used in the app
  await server.register(
    [
      requestLogger,
      requestTracing,
      secureContext,
      pulse,
      mongooseDb,
      ...(!options.disableSQS
        ? [
            createSqsClientPlugin(
              'gas_create_agreement',
              config.get('sqs.queueUrl'),
              handleCreateAgreementEvent
            ),
            createSqsClientPlugin(
              'gas_application_updated',
              config.get('sqs.gasApplicationUpdatedQueueUrl'),
              handleUpdateAgreementEvent
            )
          ]
        : []),
      errorHandlerPlugin,
      returnDataHandlerPlugin,
      router
    ].filter(Boolean)
  )

  return server
}

export { createServer }
