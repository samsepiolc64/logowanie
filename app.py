from flask import Flask

import sys
sys.path.append("./views")
sys.path.append("./config")

app = Flask(__name__)
app.config.from_pyfile('./config/config.py')

from config.create_database import *

from views.views import *

if __name__ == '__main__':
     app.run()