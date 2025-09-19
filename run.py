from flask import Flask
from config import get_config
import os

app = Flask(__name__)
app.config.from_object(get_config(os.environ.get('FLASK_ENV', 'development')))
get_config().init_app(app)

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=app.config['DEBUG']
    )
