# combined_app.py
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response

# import the app objects from your modules
import app_vuln as vuln_mod
import app_secure as secure_mod

# mount secure app at /secret and vuln app as default
application = DispatcherMiddleware(vuln_mod.app, {
    '/secret': secure_mod.app
})

# optional: a small root fallback if needed
def simple_404(environ, start_response):
    res = Response('Not Found', status=404)
    return res(environ, start_response)

#if __name__ == "__main__":
#    app.run()
