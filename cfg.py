APP_BASE = "/mnt/d/Workspaces/DEV/gspalapa-api/"
SECURITY_TRACKABLE = True
SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
SECURITY_PASSWORD_SALT = 'PALAPA_ini_PALAPA_ini_PALAPA_ini_PALAPA'
WTF_CSRF_ENABLED = False
SECURITY_TOKEN_MAX_AGE = 365 * 24 * 60 * 60 * 1000
SECRET_KEY = 'PALAPA ini PALAPA ini PALAPA ini PALAPA'
SQLALCHEMY_DATABASE_URI = 'postgres://palapa:palapa@192.168.198.133/palapa'
SQLALCHEMY_BINDS = {
    'dbdev': 'postgres://palapa:palapa@192.168.198.133/palapa_dev',
    'dbprod': 'postgres://palapa:palapa@192.168.198.133/palapa_prod',
    'dbpub': 'postgres://palapa:palapa@192.168.198.133/palapa_pub',
    'services': 'postgres://palapa:palapa@192.168.198.133/palapa'
}
SQLALCHEMY_COMMIT_ON_TEARDOWN = True
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATASTORE = 'postgres://palapa:palapa@192.168.198.133/'
GEOSERVER_REST_URL = 'http://192.168.198.133:8080/geoserver/rest/'
GEOSERVER_WMS_URL = 'http://192.168.198.133:8080/geoserver/wms?'
GEOSERVER_WFS_URL = 'http://192.168.198.133:8080/geoserver/wfs?'
GEOSERVER_WMS_OUT = 'http://192.168.198.133:8080/geoserver/wms?'
GEOSERVER_WFS_OUT = 'http://192.168.198.133:8080/geoserver/wfs?'
GEOSERVER_USER = 'palapa'
GEOSERVER_PASS = 'palapa'
GEOSERVER_THUMBNAILS = '/var/www/html/assets/thumbnails/'
GEOSERVER_LAYERS_PROP = '/mnt/d/TEMP/security/layers.properties'
GEOSERVER_SERVICES_PROP = '/mnt/d/TEMP/security/services.properties'
DATASTORE_HOST = '192.168.198.133'
DATASTORE_PORT = '5432'
DATASTORE_USER = 'palapa'
DATASTORE_PASS = 'palapa'
DATASTORE_DB = 'palapa'
UPLOAD_FOLDER = '/tmp/palapa/uploads/'
RASTER_FOLDER = '/tmp/palapa/data/'
RASTER_STORE = '/tmp/palapa/store/'
DOCUMENTS_FOLDER = '/tmp/palapa/docs/'
DOWNLOADS_FOLDER = '/tmp/palapa/downloads/'
ALLOWED_EXTENSIONS = set(['zip', 'ZIP'])
ALLOWED_VECTOR = set(['shp', 'SHP'])
ALLOWED_RASTER = set(['tiff', 'tif', 'TIF', 'TIFF'])
CSW_URL = 'http://localhost:8000/csw'
