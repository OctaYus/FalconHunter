import logging.config

logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "cli_format": {
            "format": "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s",
        }
    },
    "handlers": {
        "stdout":{
            "class": "logging.StreamHandler",
            "formatter":"cli_format",
            "level":"DEBUG",
            "stream": "ext://sys.stdout"
        },
        "filelog":{
            "class": "logging.FileHandler",
            "formatter": "cli_format",
            "encoding": "utf-8",
            "filename": "logs.log",
            "mode": "a",
            "level": "DEBUG",
        }
    },
    "loggers": {
        "Falcon": {
            "level": "DEBUG",
            "handlers": ["stdout", "filelog"],
            "propagate": False
        }
    }

}

logging.config.dictConfig(logging_config)