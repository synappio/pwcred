import os
import string

from pyramid.config import Configurator

TO_INTERPOLATE = [
    'ming.',
    ]

def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    import ming
    update_settings_from_environ(settings)
    ming.configure(**settings)
    config = Configurator(settings=settings)
    add_routes(config)
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.scan()
    return config.make_wsgi_app()

def add_routes(config):
    config.add_route('creds', '/{key}/')
    
def update_settings_from_environ(settings):
    for k,v in settings.items():
        for interp in TO_INTERPOLATE:
            if k.startswith(interp):
                t = string.Template(v)
                v1 = t.safe_substitute(os.environ)
                settings[k] = v1
                break

