import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { schema, rules, ValidationException } from '@ioc:Adonis/Core/Validator'

export default class AuthController {
  public index({ view }: HttpContextContract) {
    return view.render('authentication/login')
  }

  public async login({ auth, request, response }: HttpContextContract) {
    const loginValidation = schema.create({
      email: schema.string({ trim: true }, [rules.email(), rules.required()]),
      password: schema.string({ trim: true }, [rules.required()]),
    })

    try {
      await request.validate({ schema: loginValidation })

      const { email, password } = request.all()
      await auth.use('web').attempt(email, password)

      return response.redirect('/')
    } catch (err) {
      if (err instanceof ValidationException) {
        return response.status(401).json(err)
      }

      return response.status(401).json({
        error: 'true',
        message: 'Usuário ou senha inválidos',
      })
    }
  }

  public async logout({ auth, response }: HttpContextContract) {
    await auth.use('web').logout()
    response.redirect('/login')
  }
}
