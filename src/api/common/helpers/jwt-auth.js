import { config } from '~/src/config/index.js'
import Jwt from '@hapi/jwt'
// import Boom from '@hapi/boom'

/**
 * Validates and verifies a JWT token against a secret to extract the payload
 * which will have the 'sbi' and 'source' data
 * @param {string} authToken - The JWT token to verify and decode
 * @param {object} logger - Logger instance for error reporting
 * @returns {payload|null} The JWT payload object from the token or null if invalid/missing
 */
const extractJwtPayload = (authToken, logger) => {
  if (!authToken || authToken.trim() === '') {
    logger.error('No JWT token provided')
    return null
  }

  logger.info(
    `Attempting to decode JWT token: ${JSON.stringify({
      tokenLength: authToken.length,
      isJwtFormat: authToken.startsWith('eyJ') && authToken.includes('.')
    })}`
  )

  try {
    const decoded = Jwt.token.decode(authToken)
    logger.info('JWT token decoded successfully, attempting verification')

    // Verify the token against the secret
    Jwt.token.verify(decoded, {
      key: config.get('jwtSecret'),
      algorithms: ['HS256']
    })

    logger.info('JWT token verified successfully')
    const payload = decoded?.decoded?.payload || null

    if (payload) {
      logger.info(
        `JWT payload extracted: ${JSON.stringify({
          hasSbi: !!payload.sbi,
          hasSource: !!payload.source,
          source: payload.source
        })}`
      )
    }

    return payload
  } catch (jwtError) {
    logger.error(jwtError, `Invalid JWT token provided: ${jwtError.message}`)
    return null
  }
}

/**
 *
 * @param {object} jwtPayload - The Jwt Auth payload, that has 'sbi' and 'source'
 * @param {object} agreementData - The agreement data object
 * @returns {boolean} - if the auth payload could be verified against the sbi from the agreementData
 */
const verifyJwtPayload = (jwtPayload, agreementData) => {
  if (jwtPayload == null) {
    return false
  }

  if (jwtPayload?.source === 'entra') {
    return true
  }

  const jwtSbi = jwtPayload?.sbi != null ? String(jwtPayload.sbi) : null
  const agreementSbi =
    agreementData?.identifiers?.sbi != null
      ? String(agreementData.identifiers.sbi)
      : null

  if (jwtSbi === null && agreementSbi === null) {
    return false
  }

  return Boolean(
    jwtPayload.source === 'defra' &&
      (jwtSbi === agreementSbi || (jwtSbi && !agreementSbi))
  )
}

/**
 * Validates JWT authentication based on feature flag setting
 * @param {string} authToken - The JWT token to verify and decode
 * @param {object} agreementData - The agreement data object
 * @param {object} logger - Logger instance for error reporting
 * @returns {{valid: boolean, source: null, sbi: undefined}} - true if JWT is disabled or JWT validation passes, false otherwise
 */
const validateJwtAuthentication = (authToken, agreementData, logger) => {
  // const isJwtEnabled = config.get('featureFlags.isJwtEnabled')
  //
  // if (!agreementData && !isJwtEnabled) {
  //   throw Boom.badRequest(
  //     'Bad request, Neither JWT is enabled nor agreementId is provided'
  //   )
  // }
  //
  // if (isJwtEnabled && !authToken) {
  //   throw Boom.badRequest(
  //     'Bad request, JWT is enabled but no auth token provided in the header'
  //   )
  // }

  // logger.info(
  //   `JWT Authentication Validation Start: ${JSON.stringify({
  //     isJwtEnabled,
  //     hasAuthToken: !!authToken,
  //     authTokenLength: authToken ? authToken.length : 0,
  //     agreementSbi: agreementData?.identifiers?.sbi,
  //     agreementNumber: agreementData?.agreementNumber
  //   })}`
  // )
  //
  // if (!isJwtEnabled) {
  //   logger.warn('JWT authentication is disabled via feature flag')
  //   return { valid: true, source: null, sbi: null }
  // }

  logger.info('JWT authentication is enabled, proceeding with validation')

  const jwtPayload = extractJwtPayload(authToken, logger)
  if (!jwtPayload) {
    logger.info('JWT payload extraction failed')
    return { valid: false, source: null, sbi: null }
  }

  logger.info(
    `JWT payload extracted successfully: ${JSON.stringify({
      payloadSbi: jwtPayload.sbi,
      payloadSource: jwtPayload.source,
      agreementSbi: agreementData?.identifiers?.sbi,
      jwtSbi: jwtPayload.sbi
    })}`
  )

  const validationResult = verifyJwtPayload(jwtPayload, agreementData)

  logger.info(`JWT payload verification result: ${validationResult}`)

  return {
    valid: validationResult,
    source: jwtPayload?.source ?? null,
    sbi: jwtPayload.sbi
  }
}

export { extractJwtPayload, verifyJwtPayload, validateJwtAuthentication }
