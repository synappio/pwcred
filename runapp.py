import os
import sys

from paste.deploy import loadapp
from waitress import serve

def main():
    port = int(os.environ.get("PORT", 5000))
    app = loadapp('config:' + sys.argv[1], relative_to='.')
    serve(app, host='0.0.0.0', port=port)

if __name__ == "__main__":
    main()
